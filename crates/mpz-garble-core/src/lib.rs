//! Core components used to implement garbled circuit protocols
//!
//! This crate implements "half-gate" garbled circuits from the [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) paper.
//! This crate implements "half-gate" garbled circuits from the [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) paper.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]

pub(crate) mod circuit;
mod evaluator;
mod auth_eval;
mod generator;
mod auth_gen;
mod fpre;
pub mod store;
pub(crate) mod view;

pub use circuit::{AuthEncryptedGate, AuthEncryptedGateBatch, EncryptedGate, EncryptedGateBatch, GarbledCircuit, sigma};

pub use evaluator::{evaluate_garbled_circuits, EncryptedGateBatchConsumer, EncryptedGateConsumer, Evaluator,
    EvaluatorError, EvaluatorOutput,};
pub use auth_eval::{
     AuthEvaluator, AuthEvaluatorError, AndGateTable
};

pub use garbler::{
    EncryptedGateBatchIter, EncryptedGateIter, Garbler, GarblerError, GarblerOutput,
};
pub use auth_gen::{AuthGenerator, AuthGeneratorError};

pub use fpre::{Fpre, FpreError, gen_auth_bit_shares};
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
        Aes128,
    };
    use itybity::{FromBitIterator, IntoBitIterator, ToBits};
    use mpz_circuits::{circuits::AES128, CircuitBuilder};
    use mpz_core::{aes::FIXED_KEY_AES, Block};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    use crate::evaluator::evaluate_garbled_circuits;

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
        let x_0 = Block::random(&mut rng);
        let x_1 = x_0 ^ delta.as_block();
        let y_0 = Block::random(&mut rng);
        let y_1 = y_0 ^ delta.as_block();
        let gid: usize = 1;

        let (z_0, encrypted_gate) = gen::and_gate(cipher, &x_0, &y_0, &delta, gid);
        let z_1 = z_0 ^ delta.as_block();

        assert_eq!(ev::and_gate(cipher, &x_0, &y_0, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_0, &y_1, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_1, &y_0, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_1, &y_1, &encrypted_gate, gid), z_1);
    }

    #[test]
    fn test_garble() {
        let mut rng = StdRng::seed_from_u64(0);
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
        let input_keys = (0..AES128.input_len())
            .map(|_| rng.gen())
            .collect::<Vec<Key>>();

        let input_macs = input_keys
            .iter()
            .zip(key.iter().copied().chain(msg).into_iter_lsb0())
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();
            .zip(key.iter().copied().chain(msg).into_iter_lsb0())
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        let mut gb = Garbler::default();
        let mut ev = Evaluator::default();

        let mut gen_iter: EncryptedGateBatchIter<'_, std::slice::Iter<'_, mpz_circuits::Gate>, 128> = gen.generate_batched(&AES128, delta, input_keys).unwrap();
        let mut ev_consumer: EncryptedGateBatchConsumer<'_, std::slice::Iter<'_, mpz_circuits::Gate>, 128> = ev.evaluate_batched(&AES128, input_macs).unwrap();

        for batch in gb_iter.by_ref() {
            ev_consumer.next(batch);
        }

        let GeneratorOutput {
            outputs: output_keys,
        } = gen_iter.finish().unwrap();
        let EvaluatorOutput {
            outputs: output_macs,
            outputs: output_macs,
        } = ev_consumer.finish().unwrap();

        assert!(output_keys
            .iter()
            .zip(&output_macs)
            .zip(expected.iter_lsb0())
            .all(|((key, mac), bit)| &key.auth(bit, &delta) == mac));

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
        let input_keys = (0..AES128.input_len())
            .map(|_| rng.gen())
            .collect::<Vec<Key>>();

        let input_macs = input_keys
            .iter()
            .zip(key.iter().copied().chain(msg).into_iter_lsb0())
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        let mut gen = Generator::default();
        let mut gen_iter = gen
            .generate_batched(&AES128, delta, input_keys.clone())
            .unwrap();

        let mut gates = Vec::new();
        for batch in gen_iter.by_ref() {
            gates.extend(batch.into_array());
        }

        let garbled_circuit = GarbledCircuit { gates };

        let GeneratorOutput {
            outputs: output_keys,
        } = gen_iter.finish().unwrap();

        let outputs = evaluate_garbled_circuits(vec![
            (AES128.clone(), input_macs.clone(), garbled_circuit.clone()),
            (AES128.clone(), input_macs.clone(), garbled_circuit.clone()),
        ])
        .unwrap();

        for output in outputs {
            let EvaluatorOutput {
                outputs: output_macs,
            } = output;

            assert!(output_keys
                .iter()
                .zip(&output_macs)
                .zip(expected.iter_lsb0())
                .all(|((key, mac), bit)| &key.auth(bit, &delta) == mac));

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
        let mut rng = StdRng::seed_from_u64(0);

        let circ = xor(8);
        assert_eq!(circ.and_count(), 0);

        let a = 1u8;
        let b = 2u8;
        let expected = a ^ b;

        let delta = Delta::random(&mut rng);
        let input_keys = (0..circ.input_len())
            .map(|_| rng.gen())
            .collect::<Vec<Key>>();

        let input_macs = input_keys
            .iter()
            .zip(a.iter_lsb0().chain(b.iter_lsb0()))
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        let mut gen = Generator::default();
        let mut ev = Evaluator::default();

        let mut gen_iter = gen.generate_batched(&circ, delta, input_keys).unwrap();
        let mut ev_consumer = ev.evaluate_batched(&circ, input_macs).unwrap();

        for batch in gb_iter.by_ref() {
            ev_consumer.next(batch);
        }

        let GeneratorOutput {
            outputs: output_keys,
        } = gen_iter.finish().unwrap();
        let EvaluatorOutput {
            outputs: output_macs,
            outputs: output_macs,
        } = ev_consumer.finish().unwrap();

        assert!(output_keys
            .iter()
            .zip(&output_macs)
            .zip(expected.iter_lsb0())
            .all(|((key, mac), bit)| &key.auth(bit, &delta) == mac));

        let output: u8 = u8::from_lsb0_iter(
            output_macs
                .into_iter()
                .zip(output_keys)
                .map(|(mac, key)| mac.pointer() ^ key.pointer()),
        );

        assert_eq!(output, expected);
    }

    // Helper function to test auth garbling
    fn auth_garble(circ: &Circuit, input: Vec<bool>, input_owners: Vec<Party>) -> Vec<bool> { 
        if input.len() != input_owners.len() {
            panic!("Input length does not match input owners length");
        }

        let mut rng = StdRng::seed_from_u64(0);    
        let cipher = &(*FIXED_KEY_AES);
        
        // Insecure generation of Fpre
        let num_input_wires = circ.input_len();
        let num_and_gates = circ.and_count();
        let mut fpre = Fpre::new(0xDEAD_BEEF, num_input_wires, num_and_gates);
        fpre.generate(); // fill with random auth_bits & auth_triples

        let (fpre_gen, fpre_eval) = fpre.into_gen_eval();

        // Set inputs based on input ownership in order of node id  
        let mut eval_inputs: Vec<bool> = Vec::new();
        let mut gen_inputs: Vec<bool> = Vec::new();

        let mut idx = 0;

        for input_group in circ.inputs() {
            for node in input_group.iter() {
                if input_owners[node.id()] == Party::Evaluator {
                    eval_inputs.push(input[idx]);
                } else {
                    gen_inputs.push(input[idx]);
                }
                idx += 1;
            }
        }

        // Initialize AuthGenerator and AuthEvaluator
        let mut auth_gen = AuthGenerator::new(&circ, fpre_gen, input_owners.clone());
        let mut auth_eval = AuthEvaluator::new(&circ, fpre_eval, input_owners.clone());

        let zero_labels = (0..circ.input_len())
            .map(|_| rng.gen())
            .collect::<Vec<Block>>();

        auth_gen.initialize(zero_labels).unwrap();
        auth_eval.initialize().unwrap();

        // Evaluate free gates (XOR/NOT) before preparing derandomization bits
        auth_gen.evaluate_free_gates();
        auth_eval.garble_free_gates();

        // Prepare derandomization bits for AND gates
        let (eval_px, eval_py) = auth_eval.prepare_px_py();
        let (gen_px, gen_py) = auth_gen.prepare_px_py();

        // Garble AND gates
        let eval_gates = auth_eval.garble_and_gates(gen_px, gen_py).unwrap();
        let gen_gates = auth_gen.garble_and_gates(cipher, eval_px, eval_py).unwrap();

        // Input processing
        let gen_input_macs = auth_eval.collect_input_macs();
        let eval_input_macs = auth_gen.collect_input_macs();

        let eval_masked_inputs = auth_eval.collect_masked_inputs(eval_inputs, eval_input_macs).unwrap();
        let gen_masked_inputs = auth_gen.collect_masked_inputs(gen_inputs, gen_input_macs).unwrap();

        // Combine gen and eval masked inputs in order of node id
        let mut masked_inputs = Vec::new();
        let mut gen_idx = 0;
        let mut eval_idx = 0;
        for inputs in circ.inputs() {
            for node in inputs.iter() {
                if input_owners[node.id()] == Party::Evaluator {
                    masked_inputs.push(eval_masked_inputs[eval_idx]);
                    eval_idx += 1;
                } else {
                    masked_inputs.push(gen_masked_inputs[gen_idx]);
                    gen_idx += 1;
                }
            }
        }

        // Gen provides Eval with input labels corresponding to masked inputs
        let labels = auth_gen.collect_input_labels(&masked_inputs);
        auth_eval.set_input_labels(labels);
        auth_eval.set_masked_values(masked_inputs);

        // Evaluate garbled circuit
        auth_eval.evaluate(eval_gates, gen_gates, cipher).unwrap();

        // Collect output macs and finalize outputs
        let output_macs = auth_gen.collect_output_macs();
        let output_bits = auth_eval.finalize_outputs(output_macs).unwrap();
        return output_bits;
    }

    // Test auth garbling AES circuit
    #[test]
    fn test_auth_garble_aes(){
        let circ = &AES128;

        let key = [69u8; 16]; // AES key
        let msg = [42u8; 16]; // plaintext
        
        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut block = msg.into();
            cipher.encrypt_block(&mut block);
            block.into()
        };

        let input = key.iter_lsb0().chain(msg.iter_lsb0()).collect::<Vec<_>>();

        let mut input_owners = Vec::new();
        for input in circ.inputs() {
            for node in input.iter() {
                let id = node.id();
                if id < circ.input_len()/2 {
                    input_owners.push(Party::Evaluator);
                } else {
                    input_owners.push(Party::Generator);
                }
            }
        }

        let output_bits = auth_garble(circ, input, input_owners);
        let output: Vec<u8> = Vec::from_lsb0_iter(output_bits);
        assert_eq!(output, expected, "Output mismatch");
    }
    
    // Test auth garbling with non-contigious input ownership
    #[test]
    fn test_auth_garble_intertwined_inputs() {
        let circ = &AES128;

        let key = [69u8; 16]; // AES key
        let msg = [42u8; 16]; // plaintext
        
        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut block = msg.into();
            cipher.encrypt_block(&mut block);
            block.into()
        };

        let input = key.iter_lsb0().chain(msg.iter_lsb0()).collect::<Vec<_>>();

        let mut input_owners = Vec::new();
        for input in circ.inputs() {
            for node in input.iter() {
                let id = node.id();
                if id < circ.input_len()/4 {
                    input_owners.push(Party::Evaluator);
                } else if id < circ.input_len()/2 {
                    input_owners.push(Party::Generator);
                } else if id < 3*circ.input_len()/4 {
                    input_owners.push(Party::Evaluator);
                } else {
                    input_owners.push(Party::Generator);
                }
            }
        }

        let output_bits = auth_garble(circ, input, input_owners);
        let output: Vec<u8> = Vec::from_lsb0_iter(output_bits);
        assert_eq!(output, expected, "Output mismatch");
    }

    // Test auth garbling with only XOR gates
    #[test]
    fn test_auth_garble_xor() {
        // Only XOR gates circuit
        let builder = CircuitBuilder::new();
        let a = builder.add_input::<u8>();
        let b = builder.add_input::<u8>();
        let c = a ^ b;
        builder.add_output(c);
        let circ = builder.build().unwrap();
        assert_eq!(circ.and_count(), 0);

        let a = 1u8;
        let b = 3u8;
        let expected = a ^ b;

        let input = a.iter_lsb0().chain(b.iter_lsb0()).collect::<Vec<_>>();

        let mut input_owners = Vec::new();
        for input in circ.inputs() {
            for node in input.iter() {
                let id = node.id();
                if id < circ.input_len()/2 {
                    input_owners.push(Party::Evaluator);
                } else {
                    input_owners.push(Party::Generator);
                }
            }
        }

        let output_bits = auth_garble(&circ, input, input_owners);
        let output = u8::from_lsb0_iter(output_bits);
        assert_eq!(output, expected, "Output mismatch");
    }
    
    // Test auth garbling with a single AND gate
    #[test]
    fn test_auth_garble_and() {
        // Single AND gate circuit
        let builder = CircuitBuilder::new();
        let a = builder.add_input::<bool>();
        let b = builder.add_input::<bool>();
        let c = a & b;
        builder.add_output(c);
        let circ = builder.build().unwrap();
        assert_eq!(circ.and_count(), 1);

        let a = true;
        let b = false;
        let expected = a & b;

        let input = vec![a, b];

        let mut input_owners = Vec::new();
        for input in circ.inputs() {
            for node in input.iter() {
                let id = node.id();
                if id < circ.input_len()/2 {
                    input_owners.push(Party::Evaluator);
                } else {
                    input_owners.push(Party::Generator);
                }
            }
        }

        let output_bits = auth_garble(&circ, input, input_owners);
        let output = output_bits[0];
        assert_eq!(output, expected, "Output mismatch");
    }
    
}

// Next steps:
// 1) Output processing -- allow Gen to learn output as well, optimize by masking to sec param
// 2) Hash tweaks
// 3) Test with circuit whose input ids that are not contiguous
// 4) Propagate errors across functions
