//! Core components used to implement garbled circuit protocols
//!
//! This crate implements "half-gate" garbled circuits from the [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) paper.
//! This crate implements "half-gate" garbled circuits from the [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) paper.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]

pub(crate) mod circuit;
mod evaluator;
mod auth_eval;
mod garbler;
mod auth_gen;
mod fpre;
pub mod store;
pub(crate) mod view;

pub use circuit::{AuthHalfGate, EncryptedGate, EncryptedGateBatch, GarbledCircuit};

pub use evaluator::{evaluate_garbled_circuits, EncryptedGateBatchConsumer, EncryptedGateConsumer, Evaluator,
    EvaluatorError, EvaluatorOutput,};
pub use auth_eval::{
     AuthEvaluatorError, AuthEvalOutput, AuthEval, AuthEncryptedGateBatchConsumer, AuthEncryptedGateConsumer
};

pub use garbler::{
    EncryptedGateBatchIter, EncryptedGateIter, Garbler, GarblerError, GarblerOutput,
};
pub use auth_gen::{AuthGen, AuthGeneratorError, AuthEncryptedGateBatchIter, AuthGenOutput};

pub use fpre::{Fpre, FpreError, fpre, bit_shares_from_cot, AuthBit, AuthTriple};
pub use mpz_memory_core::correlated::{Delta, Key, Mac};

pub use mpz_circuits::Circuit;

const KB: usize = 1024;
const BYTES_PER_GATE: usize = 32;

/// Maximum size of a batch in bytes.
const MAX_BATCH_SIZE: usize = 4 * KB;

#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(missing_docs)]
pub enum Party {
    Generator,
    Evaluator,
}

/// Default amount of encrypted gates per batch.
///
/// Batches are stack allocated, so we will limit the size to `MAX_BATCH_SIZE`.
///
/// Additionally, because the size of each batch is static, if a circuit is
/// smaller than a batch we will be wasting some bandwidth sending empty bytes.
/// This puts an upper limit on that waste.
/// Additionally, because the size of each batch is static, if a circuit is
/// smaller than a batch we will be wasting some bandwidth sending empty bytes.
/// This puts an upper limit on that waste.
pub(crate) const DEFAULT_BATCH_SIZE: usize = MAX_BATCH_SIZE / BYTES_PER_GATE;

#[cfg(test)]
mod tests {
    use aes::{
        Aes128,
        cipher::{BlockEncrypt, KeyInit},
    };
    use itybity::{FromBitIterator, IntoBitIterator, ToBits};
    use mpz_circuits::circuits::{AES128, xor};
    use mpz_core::{Block, aes::FIXED_KEY_AES};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rand_chacha::ChaCha12Rng;

    use crate::evaluator::evaluate_garbled_circuits;

    use super::*;

    const SSP: usize = 40;

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
        let gid: usize = 1;

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

        let mut gb = Garbler::default();
        let mut ev = Evaluator::default();

        let mut gb_iter = gb.generate_batched(&AES128, delta, &input_keys).unwrap();
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

        let mut gb = Garbler::default();
        let mut gb_iter = gb.generate_batched(&AES128, delta, &input_keys).unwrap();

        let mut gates = Vec::new();
        for batch in gb_iter.by_ref() {
            gates.extend(batch.into_array());
        }

        let garbled_circuit = GarbledCircuit { gates };

        let GarblerOutput {
            outputs: output_keys,
        } = gb_iter.finish().unwrap();

        let outputs = evaluate_garbled_circuits(vec![
            (AES128.clone(), input_macs.clone(), garbled_circuit.clone()),
            (AES128.clone(), input_macs.clone(), garbled_circuit.clone()),
        ])
        .unwrap();

        for output in outputs {
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

        let mut gb = Garbler::default();
        let mut ev = Evaluator::default();

        let mut gb_iter = gb.generate_batched(&circ, delta, &input_keys).unwrap();
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
    
    #[test]
    fn test_auth_garble() {
        let mut rng = StdRng::seed_from_u64(0);

        let key = [69u8; 16];
        let msg = [42u8; 16];

        let circuit = &AES128;

        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut out = msg.into();
            cipher.encrypt_block(&mut out);
            out.into()
        };

        let delta_a = Delta::random(&mut rng).set_lsb(true);
        let delta_b = Delta::random(&mut rng).set_lsb(false);

        // Calculate total number of shares needed
        let bucket_size = (SSP as f64 / (circuit.and_count() as f64).log2()).ceil() as usize;
        let num_input_shares = circuit.inputs().len();
        let num_and_shares = circuit.and_count()*(3*bucket_size+1);
        let total_shares = num_input_shares + num_and_shares;

        // Get all shares in one call
        let (gen_all_shares, eval_all_shares) = 
            bit_shares_from_cot(total_shares, delta_a, delta_b)
            .unwrap();

        // Split into input and AND shares
        let (gen_input_shares, gen_and_shares) = {
            let (input, and) = gen_all_shares.split_at(num_input_shares);
            (input.to_vec(), and.to_vec())
        };
        let (eval_input_shares, eval_and_shares) = {
            let (input, and) = eval_all_shares.split_at(num_input_shares);
            (input.to_vec(), and.to_vec())
        };

        // Coin-tossing to agree on a seed
        // let seed = rand::thread_rng().gen();
        let seed = 0;

        let mut gb = AuthGen::new(seed, bucket_size);
        let mut ev = AuthEval::new(seed, bucket_size);

        let input_keys = (0..circuit.inputs().len())
            .map(|_| rng.random())
            .collect::<Vec<Key>>();

        let masked_inputs = key.iter().copied().chain(msg).into_iter_lsb0()
            .enumerate()
            .map(|(i, b)| b ^ gen_input_shares[i].bit() ^ eval_input_shares[i].bit())
            .collect::<Vec<bool>>();

        // Calculate MACs for authenticated garbling
        let input_macs = masked_inputs.iter()
            .enumerate()
            .map(|(i, b)| {
                if *b {
                    Mac::from(input_keys[i].as_block().clone()) + Mac::from(delta_a.as_block().clone())
                } else {
                    Mac::from(input_keys[i].as_block().clone())
                }
            })
            .collect::<Vec<Mac>>();    

        let (c_gen, mut g_gen) = gb.generate_pre_1(circuit, delta_a, &gen_input_shares, &gen_and_shares).unwrap();
        let (c_eval, mut g_eval) = ev.evaluate_pre_1(circuit, delta_b, &eval_input_shares, &eval_and_shares).unwrap();

        // Comm 1
        let gr_gen = g_eval.clone();
        let gr_eval = g_gen.clone();

        let d_gen = gb.generate_pre_2(delta_a, c_gen, &mut g_gen, gr_gen).unwrap();
        let d_eval = ev.evaluate_pre_2(delta_b, c_eval, &mut g_eval, gr_eval).unwrap();

        // Comm 2
        let dr_gen = d_eval.clone();    
        let dr_eval = d_gen.clone();

        let data_gen = gb.generate_pre_3(delta_a, &mut g_gen, d_gen, dr_gen).unwrap();
        let data_eval = ev.evaluate_pre_3(delta_b, &mut g_eval, d_eval, dr_eval).unwrap();

        // Comm 3 (secure equality check)

        for (g_gen, g_eval) in g_gen.iter().zip(g_eval.iter()) {
            assert_eq!(g_gen, g_eval);
        }

        // Comm 4
        let data_recv_gen = data_eval.clone();
        let data_recv_eval = data_gen.clone();

        gb.generate_pre_4(data_gen, data_recv_gen).unwrap();
        ev.evaluate_pre_4(data_eval, data_recv_eval).unwrap();

        gb.generate_free(circuit).unwrap();
        ev.evaluate_free(circuit).unwrap();

        // Comm 5
        let (px_gen, py_gen) = gb.generate_de(circuit).unwrap();
        let (px_eval, py_eval) = ev.evaluate_de(circuit).unwrap();

        let mut gen_iter: AuthEncryptedGateBatchIter<'_, std::slice::Iter<'_, mpz_circuits::Gate>> = gb.generate_batched(&AES128, delta_a, &input_keys, px_eval, py_eval).unwrap();
        let mut ev_consumer: AuthEncryptedGateBatchConsumer<'_, std::slice::Iter<'_, mpz_circuits::Gate>> = ev.evaluate_batched(&AES128, delta_b, &input_macs, masked_inputs, px_gen, py_gen).unwrap();

        for gate in gen_iter.by_ref() {
            ev_consumer.next(gate);
        }


        let AuthEvalOutput {
            output_labels: eval_output_labels,
            output_auth_bits: eval_output_auth_bits,
            auth_hash: eval_auth_hash,
            masked_output_values,
            masked_values,
        } = ev_consumer.finish().unwrap();

        let AuthGenOutput {
            output_labels: gen_output_labels,
            output_auth_bits: gen_output_auth_bits,
            auth_hash: gen_auth_hash,
        } = gen_iter.finish(masked_values).unwrap();

        // authentication check
        assert_eq!(gen_auth_hash, eval_auth_hash);

        let masks = gen_output_auth_bits.iter()
            .zip(eval_output_auth_bits.iter())
            .map(|(gen_auth_bit, eval_auth_bit)| gen_auth_bit.bit() ^ eval_auth_bit.bit())
            .collect::<Vec<bool>>();
        
        // Unmask the output
        let output: Vec<u8> = Vec::from_lsb0_iter(
            masked_output_values
                .clone()
                .into_iter()
                .enumerate()
                .map(|(i, masked_value)| masked_value ^ masks[i]),
        );

        assert_eq!(output, expected);   

        // Check output labels
        for (i, (gen_label, eval_label)) in gen_output_labels.iter().zip(eval_output_labels.iter()).enumerate() {
            let xor = gen_label.as_block() ^ eval_label.as_block();
            let masked_value = masked_output_values[i];
            let expected = delta_a.mul_bool(masked_value);
            assert_eq!(xor, expected);
        }
    }
}
