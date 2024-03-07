//! An implementation of the [`KOS15`](https://eprint.iacr.org/2015/546.pdf) oblivious transfer extension protocol.

mod config;
mod error;
pub mod msgs;
mod receiver;
mod sender;

pub use config::{
    ReceiverConfig, ReceiverConfigBuilder, ReceiverConfigBuilderError, SenderConfig,
    SenderConfigBuilder, SenderConfigBuilderError,
};
pub use error::{ReceiverError, ReceiverVerifyError, SenderError};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
pub use receiver::{state as receiver_state, PayloadRecord, Receiver, ReceiverKeys};
pub use sender::{state as sender_state, Sender, SenderKeys};

/// Computational security parameter
pub const CSP: usize = 128;
/// Statistical security parameter
pub const SSP: usize = 128;
/// Rng to use for secret sharing the IKNP matrix.
pub(crate) type Rng = ChaCha20Rng;
/// Rng seed type
pub(crate) type RngSeed = <Rng as SeedableRng>::Seed;

/// AES-128 CTR used for encryption.
pub(crate) type Aes128Ctr = ctr::Ctr64LE<aes::Aes128>;

/// Pads the number of OTs to accommodate for the KOS extension check and
/// the extension matrix transpose optimization.
pub fn pad_ot_count(mut count: usize) -> usize {
    // Add OTs for the KOS extension check.
    count += CSP + SSP;
    // Round up the OTs to extend to the nearest multiple of 64 (matrix transpose optimization).
    (count + 63) & !63
}

/// Returns the size in bytes of the extension matrix for a given number of OTs.
pub fn extension_matrix_size(count: usize) -> usize {
    count * CSP / 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use itybity::ToBits;
    use rstest::*;

    use mpz_core::Block;

    use rand::Rng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[fixture]
    fn choices() -> Vec<bool> {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        (0..128).map(|_| rng.gen()).collect()
    }

    #[fixture]
    fn data() -> Vec<[Block; 2]> {
        let mut rng = ChaCha12Rng::seed_from_u64(1);
        (0..128)
            .map(|_| [rng.gen::<[u8; 16]>().into(), rng.gen::<[u8; 16]>().into()])
            .collect()
    }

    #[fixture]
    fn delta() -> Block {
        let mut rng = ChaCha12Rng::seed_from_u64(2);
        rng.gen::<[u8; 16]>().into()
    }

    #[fixture]
    fn receiver_seeds() -> [[Block; 2]; CSP] {
        let mut rng = ChaCha12Rng::seed_from_u64(3);
        std::array::from_fn(|_| [rng.gen(), rng.gen()])
    }

    #[fixture]
    fn sender_seeds(delta: Block, receiver_seeds: [[Block; 2]; CSP]) -> [Block; CSP] {
        delta
            .iter_lsb0()
            .zip(receiver_seeds)
            .map(|(b, seeds)| if b { seeds[1] } else { seeds[0] })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[fixture]
    fn chi_seed() -> Block {
        let mut rng = ChaCha12Rng::seed_from_u64(4);
        rng.gen::<[u8; 16]>().into()
    }

    #[fixture]
    fn expected(data: Vec<[Block; 2]>, choices: Vec<bool>) -> Vec<Block> {
        data.iter()
            .zip(choices.iter())
            .map(|([a, b], choice)| if *choice { *b } else { *a })
            .collect()
    }

    #[rstest]
    fn test_kos_extension(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
        chi_seed: Block,
        choices: Vec<bool>,
        data: Vec<[Block; 2]>,
        expected: Vec<Block>,
    ) {
        let sender = Sender::new(SenderConfig::default());
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(delta, sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        let receiver_setup = receiver.extend(choices.len() + 256).unwrap();
        sender.extend(data.len() + 256, receiver_setup).unwrap();

        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(chi_seed, receiver_check).unwrap();

        let mut receiver_keys = receiver.keys(choices.len()).unwrap();
        let derandomize = receiver_keys.derandomize(&choices).unwrap();

        let mut sender_keys = sender.keys(data.len()).unwrap();
        sender_keys.derandomize(derandomize).unwrap();
        let payload = sender_keys.encrypt_blocks(&data).unwrap();

        let received = receiver_keys.decrypt_blocks(payload).unwrap();

        assert_eq!(received, expected);
    }

    #[rstest]
    fn test_kos_extension_bytes(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
        chi_seed: Block,
        choices: Vec<bool>,
        data: Vec<[Block; 2]>,
        expected: Vec<Block>,
    ) {
        let sender = Sender::new(SenderConfig::default());
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(delta, sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        let receiver_setup = receiver.extend(choices.len() + 256).unwrap();
        sender.extend(data.len() + 256, receiver_setup).unwrap();

        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(chi_seed, receiver_check).unwrap();

        let mut receiver_keys = receiver.keys(choices.len()).unwrap();
        let derandomize = receiver_keys.derandomize(&choices).unwrap();

        let data: Vec<_> = data
            .iter()
            .map(|[a, b]| [a.to_bytes(), b.to_bytes()])
            .collect();

        let mut sender_keys = sender.keys(data.len()).unwrap();
        sender_keys.derandomize(derandomize).unwrap();
        let payload = sender_keys.encrypt_bytes(&data).unwrap();

        let received = receiver_keys.decrypt_bytes::<16>(payload).unwrap();

        let expected = expected.iter().map(|b| b.to_bytes()).collect::<Vec<_>>();

        assert_eq!(received, expected);
    }

    #[rstest]
    fn test_kos_extension_stream_extends(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
        chi_seed: Block,
        choices: Vec<bool>,
        data: Vec<[Block; 2]>,
        expected: Vec<Block>,
    ) {
        let sender = Sender::new(SenderConfig::default());
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(delta, sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        let receiver_setup = receiver.extend(choices.len()).unwrap();
        sender.extend(choices.len(), receiver_setup).unwrap();

        // Extend 256 more
        let receiver_setup = receiver.extend(256).unwrap();
        sender.extend(256, receiver_setup).unwrap();

        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(chi_seed, receiver_check).unwrap();

        let mut receiver_keys = receiver.keys(choices.len()).unwrap();
        let derandomize = receiver_keys.derandomize(&choices).unwrap();

        let mut sender_keys = sender.keys(data.len()).unwrap();
        sender_keys.derandomize(derandomize).unwrap();
        let payload = sender_keys.encrypt_blocks(&data).unwrap();

        let received = receiver_keys.decrypt_blocks(payload).unwrap();

        assert_eq!(received, expected);
    }

    #[rstest]
    fn test_kos_extension_multiple_extends_fail(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
        chi_seed: Block,
    ) {
        let sender = Sender::new(SenderConfig::default());
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(delta, sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        let receiver_setup = receiver.extend(256).unwrap();
        sender.extend(256, receiver_setup).unwrap();

        // Perform check
        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(chi_seed, receiver_check).unwrap();

        // Extending more should fail
        let receiver_setup = receiver.extend(256).unwrap_err();

        assert!(matches!(receiver_setup, ReceiverError::InvalidState(_)));
    }

    #[rstest]
    fn test_kos_extension_insufficient_setup(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
        chi_seed: Block,
    ) {
        let sender = Sender::new(SenderConfig::default());
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(delta, sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        let receiver_setup = receiver.extend(64).unwrap();
        sender.extend(64, receiver_setup).unwrap();

        // Perform check
        let err = receiver.check(chi_seed).unwrap_err();

        assert!(matches!(err, ReceiverError::InsufficientSetup(_, _)));
    }

    #[rstest]
    fn test_kos_extension_bad_consistency_check(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
        chi_seed: Block,
    ) {
        let sender = Sender::new(SenderConfig::default());
        let receiver = Receiver::new(ReceiverConfig::default());

        let mut sender = sender.setup(delta, sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        let mut receiver_setup = receiver.extend(512).unwrap();

        // Flip a bit in the receiver's extension message (breaking the mono-chrome choice vector)
        *receiver_setup.us.first_mut().unwrap() ^= 1;

        sender.extend(512, receiver_setup).unwrap();

        let receiver_check = receiver.check(chi_seed).unwrap();
        let err = sender.check(chi_seed, receiver_check).unwrap_err();

        assert!(matches!(err, SenderError::ConsistencyCheckFailed));
    }

    #[rstest]
    fn test_kos_extension_verify_messages(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
        chi_seed: Block,
        choices: Vec<bool>,
        data: Vec<[Block; 2]>,
        expected: Vec<Block>,
    ) {
        let sender = Sender::new(SenderConfig::default());
        let receiver = Receiver::new(ReceiverConfig::builder().sender_commit().build().unwrap());

        let mut sender = sender.setup(delta, sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        let receiver_setup = receiver.extend(choices.len() + 256).unwrap();
        sender.extend(data.len() + 256, receiver_setup).unwrap();

        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(chi_seed, receiver_check).unwrap();

        let mut receiver_keys = receiver.keys(choices.len()).unwrap();
        let derandomize = receiver_keys.derandomize(&choices).unwrap();

        let mut sender_keys = sender.keys(data.len()).unwrap();
        sender_keys.derandomize(derandomize).unwrap();
        let payload = sender_keys.encrypt_blocks(&data).unwrap();

        let received = receiver_keys.decrypt_blocks(payload).unwrap();

        assert_eq!(received, expected);

        let receiver = receiver.start_verification(delta).unwrap();

        receiver.remove_record(0).unwrap().verify(&data).unwrap();
    }

    #[rstest]
    fn test_kos_extension_verify_messages_fail(
        delta: Block,
        sender_seeds: [Block; CSP],
        receiver_seeds: [[Block; 2]; CSP],
        chi_seed: Block,
        choices: Vec<bool>,
        mut data: Vec<[Block; 2]>,
        expected: Vec<Block>,
    ) {
        let sender = Sender::new(SenderConfig::default());
        let receiver = Receiver::new(ReceiverConfig::builder().sender_commit().build().unwrap());

        let mut sender = sender.setup(delta, sender_seeds);
        let mut receiver = receiver.setup(receiver_seeds);

        let receiver_setup = receiver.extend(choices.len() + 256).unwrap();
        sender.extend(data.len() + 256, receiver_setup).unwrap();

        let receiver_check = receiver.check(chi_seed).unwrap();
        sender.check(chi_seed, receiver_check).unwrap();

        let mut receiver_keys = receiver.keys(choices.len()).unwrap();
        let derandomize = receiver_keys.derandomize(&choices).unwrap();

        let mut sender_keys = sender.keys(data.len()).unwrap();
        sender_keys.derandomize(derandomize).unwrap();
        let payload = sender_keys.encrypt_blocks(&data).unwrap();

        let received = receiver_keys.decrypt_blocks(payload).unwrap();

        assert_eq!(received, expected);

        data[0][0] = Block::default();

        let receiver = receiver.start_verification(delta).unwrap();

        let err = receiver
            .remove_record(0)
            .unwrap()
            .verify(&data)
            .unwrap_err();

        assert!(matches!(
            err,
            ReceiverError::ReceiverVerifyError(ReceiverVerifyError::InconsistentPayload)
        ));
    }
}
