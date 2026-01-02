//! Core components used to implement garbled circuit protocols
//!
//! This crate implements "half-gate" garbled circuits from the [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) paper.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]

pub(crate) mod circuit;
mod evaluator;
mod garbler;
pub mod store;
pub(crate) mod view;

pub use circuit::{EncryptedGate, EncryptedGateBatch, GarbledCircuit};
pub use evaluator::{
    EncryptedGateBatchConsumer, EncryptedGateConsumer, Evaluator, EvaluatorError, EvaluatorOutput,
    EvaluatorWorker, evaluate_garbled_circuits,
};
pub use garbler::{
    EncryptedGateBatchIter, EncryptedGateIter, Garbler, GarblerError, GarblerOutput, GarblerWorker,
};
pub use mpz_memory_core::correlated::{Delta, Key, Mac};
use serde::{Deserialize, Serialize};
pub use view::FlushView;

const KB: usize = 1024;
const BYTES_PER_GATE: usize = 32;

/// Maximum size of a batch in bytes.
const MAX_BATCH_SIZE: usize = 4 * KB;

/// Default amount of encrypted gates per batch.
///
/// Batches are stack allocated, so we will limit the size to `MAX_BATCH_SIZE`.
///
/// Additionally, because the size of each batch is static, if a circuit is
/// smaller than a batch we will be wasting some bandwidth sending empty bytes.
/// This puts an upper limit on that waste.
pub(crate) const DEFAULT_BATCH_SIZE: usize = MAX_BATCH_SIZE / BYTES_PER_GATE;

/// Setup message passed from the garbler to the evaluator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SetupMsg {
    /// Initial AND gate id.
    initial_gid: u128,
    /// Key for the cipher used to encrypt the gates.
    key: [u8; 16],
}

#[cfg(test)]
mod tests {
    use aes::{
        Aes128,
        cipher::{BlockCipherEncrypt, KeyInit},
    };
    use itybity::{FromBitIterator, IntoBitIterator, ToBits};
    use mpz_circuits::{AES128, circuits::xor};
    use mpz_core::{Block, aes::FIXED_KEY_AES};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rand_chacha::ChaCha12Rng;

    use crate::evaluator::evaluate_garbled_circuits;

    use super::*;

    #[test]
    fn test_and_gate() {
        use crate::{evaluator as ev, garbler as gb};

        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let cipher = &(*FIXED_KEY_AES);

        let delta = Delta::random(&mut rng);
        let x_0 = Block::random(&mut rng);
        let x_1 = x_0 ^ delta.as_block();
        let y_0 = Block::random(&mut rng);
        let y_1 = y_0 ^ delta.as_block();
        let gid: u128 = 1;

        let (z_0, encrypted_gate) = gb::and_gate(cipher, &x_0, &y_0, &delta, gid);
        let z_1 = z_0 ^ delta.as_block();

        assert_eq!(ev::and_gate(cipher, &x_0, &y_0, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_0, &y_1, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_1, &y_0, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_1, &y_1, &encrypted_gate, gid), z_1);
    }

    #[test]
    fn test_garble() {
        let mut rng = StdRng::seed_from_u64(0);

        let key = [69u8; 16];
        let msg = [42u8; 16];

        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut out = msg.into();
            cipher.encrypt_block(&mut out);
            out.into()
        };

        let delta = Delta::random(&mut rng);
        let input_keys = (0..AES128.inputs().len())
            .map(|_| rng.random())
            .collect::<Vec<Key>>();

        let input_macs = input_keys
            .iter()
            .zip(key.iter().copied().chain(msg).into_iter_lsb0())
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        let mut gb = Garbler::new(rng.random(), delta);
        let setup = gb.setup().unwrap();
        let mut ev = Evaluator::default();
        ev.setup(setup).unwrap();

        let mut gb_iter = gb.generate_batched(&AES128, &input_keys).unwrap();
        let mut ev_consumer = ev.evaluate_batched(&AES128, &input_macs).unwrap();

        for batch in gb_iter.by_ref() {
            ev_consumer.next(batch);
        }

        let GarblerOutput {
            outputs: output_keys,
        } = gb_iter.finish().unwrap();
        let EvaluatorOutput {
            outputs: output_macs,
        } = ev_consumer.finish().unwrap();

        assert!(
            output_keys
                .iter()
                .zip(&output_macs)
                .zip(expected.iter_lsb0())
                .all(|((key, mac), bit)| &key.auth(bit, &delta) == mac)
        );

        let output: Vec<u8> = Vec::from_lsb0_iter(
            output_macs
                .into_iter()
                .zip(output_keys)
                .map(|(mac, key)| mac.pointer() ^ key.pointer()),
        );

        assert_eq!(output, expected);
    }

    #[test]
    fn test_garble_preprocessed() {
        let mut rng = StdRng::seed_from_u64(0);

        let key = [69u8; 16];
        let msg = [42u8; 16];

        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut out = msg.into();
            cipher.encrypt_block(&mut out);
            out.into()
        };

        let delta = Delta::random(&mut rng);
        let input_keys = (0..AES128.inputs().len())
            .map(|_| rng.random())
            .collect::<Vec<Key>>();

        let input_macs = input_keys
            .iter()
            .zip(key.iter().copied().chain(msg).into_iter_lsb0())
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        let mut gb = Garbler::new(rng.random(), delta);
        let setup = gb.setup().unwrap();
        let mut ev = Evaluator::default();
        ev.setup(setup).unwrap();

        // Allocate 2 workers from garbler
        let gb_worker1 = gb.alloc_worker(AES128.and_count()).unwrap();
        let gb_worker2 = gb.alloc_worker(AES128.and_count()).unwrap();

        // Garble circuit 1 with worker1
        let mut gb_iter1 = gb_worker1.generate_batched(&AES128, &input_keys).unwrap();
        let mut gates1 = Vec::new();
        for batch in gb_iter1.by_ref() {
            gates1.extend(batch.into_array());
        }
        let garbled_circuit1 = GarbledCircuit { gates: gates1 };
        let GarblerOutput {
            outputs: output_keys1,
        } = gb_iter1.finish().unwrap();

        // Garble circuit 2 with worker2
        let mut gb_iter2 = gb_worker2.generate_batched(&AES128, &input_keys).unwrap();
        let mut gates2 = Vec::new();
        for batch in gb_iter2.by_ref() {
            gates2.extend(batch.into_array());
        }
        let garbled_circuit2 = GarbledCircuit { gates: gates2 };
        let GarblerOutput {
            outputs: output_keys2,
        } = gb_iter2.finish().unwrap();

        // Allocate 2 workers from evaluator
        let outputs = evaluate_garbled_circuits(
            vec![
                (AES128.clone(), input_macs.clone(), garbled_circuit1),
                (AES128.clone(), input_macs.clone(), garbled_circuit2),
            ],
            vec![
                ev.alloc_worker(AES128.and_count()).unwrap(),
                ev.alloc_worker(AES128.and_count()).unwrap(),
            ],
        )
        .unwrap();

        for (output, output_keys) in outputs.into_iter().zip([output_keys1, output_keys2]) {
            let EvaluatorOutput {
                outputs: output_macs,
            } = output;

            assert!(
                output_keys
                    .iter()
                    .zip(&output_macs)
                    .zip(expected.iter_lsb0())
                    .all(|((key, mac), bit)| &key.auth(bit, &delta) == mac)
            );

            let output: Vec<u8> = Vec::from_lsb0_iter(
                output_macs
                    .into_iter()
                    .zip(&output_keys)
                    .map(|(mac, key)| mac.pointer() ^ key.pointer()),
            );

            assert_eq!(output, expected);
        }
    }

    // Tests garbling a circuit with no AND gates
    #[test]
    fn test_garble_no_and() {
        let mut rng = StdRng::seed_from_u64(0);

        let circ = xor(8);
        assert_eq!(circ.and_count(), 0);

        let a = 1u8;
        let b = 2u8;
        let expected = a ^ b;

        let delta = Delta::random(&mut rng);
        let input_keys = (0..circ.inputs().len())
            .map(|_| rng.random())
            .collect::<Vec<Key>>();

        let input_macs = input_keys
            .iter()
            .zip(a.iter_lsb0().chain(b.iter_lsb0()))
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        let mut gb = Garbler::new(rng.random(), delta);
        let setup = gb.setup().unwrap();
        let mut ev = Evaluator::default();
        ev.setup(setup).unwrap();

        let mut gb_iter = gb.generate_batched(&circ, &input_keys).unwrap();
        let mut ev_consumer = ev.evaluate_batched(&circ, &input_macs).unwrap();

        for batch in gb_iter.by_ref() {
            ev_consumer.next(batch);
        }

        let GarblerOutput {
            outputs: output_keys,
        } = gb_iter.finish().unwrap();
        let EvaluatorOutput {
            outputs: output_macs,
        } = ev_consumer.finish().unwrap();

        assert!(
            output_keys
                .iter()
                .zip(&output_macs)
                .zip(expected.iter_lsb0())
                .all(|((key, mac), bit)| &key.auth(bit, &delta) == mac)
        );

        let output: u8 = u8::from_lsb0_iter(
            output_macs
                .into_iter()
                .zip(output_keys)
                .map(|(mac, key)| mac.pointer() ^ key.pointer()),
        );

        assert_eq!(output, expected);
    }
}
