//! An implementation of the Chou-Orlandi [`CO15`](https://eprint.iacr.org/2015/267.pdf) oblivious transfer protocol.

mod config;
mod error;
pub mod msgs;
mod receiver;
mod sender;

pub use config::{
    ReceiverConfig, ReceiverConfigBuilder, ReceiverConfigBuilderError, SenderConfig,
    SenderConfigBuilder, SenderConfigBuilderError,
};
pub use error::{ReceiverError, SenderError, SenderVerifyError};
pub use receiver::{state as receiver_state, Receiver};
pub use sender::{state as sender_state, Sender};

use blake3::Hasher;
use curve25519_dalek::ristretto::RistrettoPoint;
use mpz_core::Block;

/// Hashes a ristretto point to a symmetric key
///
/// Prepending a tweak is suggested in Section 2, "Non-Malleability in Practice"
pub(crate) fn hash_point(point: &RistrettoPoint, tweak: u128) -> Block {
    // Compute H(tweak || point)
    let mut h = Hasher::new();
    h.update(&tweak.to_be_bytes());
    h.update(point.compress().as_bytes());
    let digest = h.finalize();
    let digest: &[u8; 32] = digest.as_bytes();

    // Copy the first 16 bytes into a Block
    let mut block = [0u8; 16];
    block.copy_from_slice(&digest[..16]);
    block.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use itybity::IntoBitIterator;
    use rstest::*;

    use rand::Rng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    const SENDER_SEED: [u8; 32] = [0u8; 32];
    const RECEIVER_SEED: [u8; 32] = [1u8; 32];

    #[fixture]
    fn choices() -> Vec<bool> {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        (0..128).map(|_| rng.gen()).collect()
    }

    #[fixture]
    fn data() -> Vec<[Block; 2]> {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        (0..128)
            .map(|_| [rng.gen::<[u8; 16]>().into(), rng.gen::<[u8; 16]>().into()])
            .collect()
    }

    #[fixture]
    fn expected(data: Vec<[Block; 2]>, choices: Vec<bool>) -> Vec<Block> {
        data.iter()
            .zip(choices.iter())
            .map(|([a, b], choice)| if *choice { *b } else { *a })
            .collect()
    }

    fn setup(
        sender_config: SenderConfig,
        receiver_config: ReceiverConfig,
    ) -> (Sender<sender_state::Setup>, Receiver<receiver_state::Setup>) {
        let sender = Sender::new_with_seed(sender_config, SENDER_SEED);
        let receiver = Receiver::new_with_seed(receiver_config, RECEIVER_SEED);

        let (sender_setup, sender) = sender.setup();
        let receiver = receiver.setup(sender_setup);

        (sender, receiver)
    }

    #[rstest]
    fn test_ot_pass(choices: Vec<bool>, data: Vec<[Block; 2]>, expected: Vec<Block>) {
        let (mut sender, mut receiver) = setup(SenderConfig::default(), ReceiverConfig::default());

        let receiver_payload = receiver.receive_random(&choices);
        let sender_payload = sender.send(&data, receiver_payload).unwrap();

        let received_data = receiver.receive(sender_payload).unwrap();

        assert_eq!(received_data, expected);
    }

    #[rstest]
    fn test_multiple_ot_pass(choices: Vec<bool>, data: Vec<[Block; 2]>, expected: Vec<Block>) {
        let (mut sender, mut receiver) = setup(SenderConfig::default(), ReceiverConfig::default());

        let receiver_payload = receiver.receive_random(&choices);
        let sender_payload = sender.send(&data, receiver_payload).unwrap();

        let received_data = receiver.receive(sender_payload).unwrap();

        assert_eq!(received_data, expected);

        let receiver_payload = receiver.receive_random(&choices);
        let sender_payload = sender.send(&data, receiver_payload).unwrap();

        let received_data = receiver.receive(sender_payload).unwrap();

        assert_eq!(received_data, expected);
    }

    #[rstest]
    fn test_committed_ot_receiver_pass(
        choices: Vec<bool>,
        data: Vec<[Block; 2]>,
        expected: Vec<Block>,
    ) {
        let (mut sender, mut receiver) = setup(
            SenderConfig::builder().receiver_commit().build().unwrap(),
            ReceiverConfig::builder().receiver_commit().build().unwrap(),
        );

        let receiver_payload = receiver.receive_random(&choices);
        let sender_payload = sender.send(&data, receiver_payload).unwrap();

        let received_data = receiver.receive(sender_payload).unwrap();

        assert_eq!(received_data, expected);

        let receiver_reveal = receiver.reveal_choices().unwrap();

        let verified_choices = sender
            .verify_choices(RECEIVER_SEED, receiver_reveal)
            .unwrap();

        assert_eq!(choices, verified_choices.into_lsb0_vec());
    }

    #[rstest]
    fn test_committed_ot_receiver_cheat_choice(
        choices: Vec<bool>,
        data: Vec<[Block; 2]>,
        expected: Vec<Block>,
    ) {
        let (mut sender, mut receiver) = setup(
            SenderConfig::builder().receiver_commit().build().unwrap(),
            ReceiverConfig::builder().receiver_commit().build().unwrap(),
        );

        let receiver_payload = receiver.receive_random(&choices);
        let sender_payload = sender.send(&data, receiver_payload).unwrap();

        let received_data = receiver.receive(sender_payload).unwrap();

        assert_eq!(received_data, expected);

        let mut receiver_reveal = receiver.reveal_choices().unwrap();

        // Flip a bit
        receiver_reveal.choices[0] ^= 1;

        let err = sender
            .verify_choices(RECEIVER_SEED, receiver_reveal)
            .unwrap_err();

        assert!(matches!(
            err,
            SenderError::VerifyError(error::SenderVerifyError::InconsistentChoice)
        ));
    }
}
