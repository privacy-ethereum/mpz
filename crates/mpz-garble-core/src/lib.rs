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

// use mpz_circuits::{
//     Circuit, Gate,
// };

pub use evaluator::{evaluate_garbled_circuits, EncryptedGateBatchConsumer, EncryptedGateConsumer, Evaluator,
    EvaluatorError, EvaluatorOutput,};
pub use auth_eval::{
     AuthEvaluator, AuthEvaluatorError, AndGateTable
};

pub use garbler::{
    EncryptedGateBatchIter, EncryptedGateIter, Garbler, GarblerError, GarblerOutput,
};
pub use auth_gen::{AuthGenerator, AuthGeneratorError};

pub use fpre::{Fpre, FpreError};
pub use mpz_memory_core::correlated::{Delta, Key, Mac};

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

    // // This small utility collects the `z` wire ID for each AND gate in topological order
    // fn collect_and_wires(circ: &Circuit) -> Vec<usize> {
    //     let mut wires = Vec::new();
    //     for gate in circ.gates() {
    //         if let Gate::And { x, y, z } = gate {
    //             wires.push(z.id());
    //         }
    //     }
    //     wires
    // }

    #[test]
    fn test_auth_garble() {

        let mut rng = StdRng::seed_from_u64(0);
        
        let cipher = &(*FIXED_KEY_AES);
        let circ = &AES128;

        // // Only XOR gates circuit
        // let builder = CircuitBuilder::new();
        // let a = builder.add_input::<u8>();
        // let b = builder.add_input::<u8>();
        // let c = a ^ b;
        // builder.add_output(c);
        // let circ = builder.build().unwrap();
        // assert_eq!(circ.and_count(), 0);

        // // Single AND gate circuit
        // let builder = CircuitBuilder::new();
        // let a = builder.add_input::<bool>();
        // let b = builder.add_input::<bool>();
        // let c = a & b;
        // builder.add_output(c);
        // let circ = builder.build().unwrap();
        // assert_eq!(circ.and_count(), 1);

        // let a = false;
        // let b = false;
        // let c = a & b;

        // // // We'll do a small single-process test to encrypt `msg` with `key`.
        let key = [69u8; 16]; // AES key
        let msg = [42u8; 16]; // plaintext
        // The "expected" result by doing real AES
        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut block = msg.into();
            cipher.encrypt_block(&mut block);
            block.into()
        };


        // let a = 1u8;
        // let b = 2u8;
        // let expected = a ^ b;
        
        // 2) Create an Fpre with enough wires for AES-128
        let num_input_wires = circ.input_len(); // e.g. 256 bits
        let num_and_gates = circ.and_count();   // e.g. some # of AND gates
        let mut fpre = Fpre::new(0xDEAD_BEEF, num_input_wires, num_and_gates);
        fpre.generate(); // fill the auth_bits & auth_triples

        // 3) Extract fpre_gen & fpre_eval
        let (fpre_gen, fpre_eval) = fpre.into_gen_eval();

        // 4) Build an AuthGenerator and AuthEvaluator referencing the same circuit
        let mut auth_gen = AuthGenerator::new(&circ, fpre_gen);
        let mut auth_eval = AuthEvaluator::new(&circ, fpre_eval);

        let eval_inputs = key.iter_lsb0()
            .chain(msg.iter_lsb0())
            .collect::<Vec<_>>();

        // println!("eval_inputs = {:?}", eval_inputs);

        let zero_labels = (0..circ.input_len())
            .map(|_| rng.gen())
            .collect::<Vec<Block>>();

        // 6) Initialize generator & evaluator with these input wire keys (toy approach)
        auth_gen.initialize(zero_labels).unwrap();
        auth_eval.initialize().unwrap();

        // // 7) Evaluate free gates (XOR/NOT)
        auth_gen.evaluate_free_gates();
        auth_eval.garble_free_gates();

        let (eval_px, eval_py) = auth_eval.prepare_px_py();
        let (gen_px, gen_py) = auth_gen.prepare_px_py();

        let eval_gates = auth_eval.garble_and_gates(gen_px, gen_py).unwrap();
        let gen_gates = auth_gen.garble_and_gates(cipher, eval_px, eval_py).unwrap();

        let input_macs = auth_gen.collect_input_macs();
        // let r = input_macs.iter().map(|mac| mac.pointer()).collect::<Vec<_>>();
        // println!("r = {:?}", r);
        // let s = circ
        //     .inputs()
        //     .iter()
        //     .flat_map(|input_group| {
        //         input_group.iter().map(|node| {
        //             auth_eval.auth_bits[node.id()].bit()
        //         })
        //     })
        //     .collect::<Vec<_>>();
        // println!("s = {:?}", s);
        let masked_inputs = auth_eval.collect_masked_inputs(eval_inputs, input_macs).unwrap();
        // println!("masked_inputs = {:?}", masked_inputs);
        let eval_labels = auth_gen.collect_input_labels(masked_inputs);
        // let xor = eval_labels.iter().zip(zero_labels_copy.iter()).map(|(a, b)| a ^ b).collect::<Vec<_>>();
        // println!("xor = {:?}", xor);
        auth_eval.set_input_labels(eval_labels);
        auth_eval.evaluate(eval_gates, gen_gates, cipher).unwrap(); // TODO

        let output_macs = auth_gen.collect_output_macs();
        let output_bits = auth_eval.finalize_outputs(output_macs).unwrap();

        let output: Vec<u8> = Vec::from_lsb0_iter(output_bits);
        // let output = output_bits[0];

        assert_eq!(output, expected, "Final ciphertext mismatch");
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
}

// Next steps:
// 1) Input processing -- differentiate between Alice and Bob's inputs -- right now Bob picks all inputs
// 2) Robust testing with different circuits
// ---
// 3) Output processing -- allow Gen to learn output as well, optimize by masking to sec param
// 4) Hash tweaks

