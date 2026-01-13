//! Integration tests for the three-halves garbling scheme
//!
//! These tests verify that the Garbler and Evaluator work correctly together.
//! They are organized by circuit complexity.

use aes::{
    Aes128 as AesCipher,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use itybity::{FromBitIterator, IntoBitIterator, ToBits};
use mpz_circuits::{AES128, CircuitBuilder, circuits::xor};
use mpz_core::Block;
use mpz_memory_core::correlated::{Delta, Key, Mac};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha12Rng;

use super::{Evaluator, EvaluatorOutput, Garbler, GarblerOutput};

// ==============================================================================
// Small Circuit Tests (1-4 AND gates)
//
// Basic tests verify correctness on small circuits
// ==============================================================================

/// Helper function to run a garble-evaluate-verify test
fn test_circuit_correctness<F>(circuit_builder: F, input_combinations: &[(Vec<bool>, bool)])
where
    F: Fn() -> mpz_circuits::Circuit,
{
    let circ = circuit_builder();

    for (input_bits, expected_output) in input_combinations {
        let mut rng = ChaCha12Rng::seed_from_u64(42);
        let delta = Delta::random(&mut rng);

        let input_keys: Vec<Key> = (0..input_bits.len())
            .map(|_| {
                let block: Block = rng.random();
                block.into()
            })
            .collect();

        // Garble the circuit
        let mut gb = Garbler::default();
        let mut gb_iter = gb.generate(&circ, delta, &input_keys, &mut rng).unwrap();

        let mut encrypted_gates = Vec::new();
        while let Some(gate) = gb_iter.next() {
            encrypted_gates.push(gate);
        }

        let GarblerOutput {
            outputs: output_labels,
        } = gb_iter.finish().unwrap();

        // Select input MACs based on input bits
        // Key is 0-label, Key ⊕ Δ is 1-label
        let delta_block = *delta.as_block();
        let input_macs: Vec<Mac> = input_bits
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                let key_block = *input_keys[i].as_block();
                if bit {
                    (key_block ^ delta_block).into()
                } else {
                    key_block.into()
                }
            })
            .collect();

        // Evaluate the circuit
        let mut ev = Evaluator::default();
        let mut ev_consumer = ev.evaluate(&circ, &input_macs).unwrap();

        for gate in encrypted_gates {
            ev_consumer.next(gate);
        }

        let EvaluatorOutput {
            outputs: output_macs,
        } = ev_consumer.finish().unwrap();

        // Verify output
        let false_label = Mac::from(*output_labels[0].as_block());
        let true_label = Mac::from(*output_labels[0].as_block() ^ *delta.as_block());
        let expected_mac = if *expected_output {
            &true_label
        } else {
            &false_label
        };

        assert_eq!(
            &output_macs[0], expected_mac,
            "Failed for inputs {:?}: expected {}, got wrong output",
            input_bits, expected_output
        );
    }
}

/// Test: Single AND gate (1 gate)
#[test]
fn test_single_and_gate() {
    let circuit_builder = || {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_input();
        let b = builder.add_input();
        let out = builder.add_and_gate(a, b);
        builder.add_output(out);
        builder.build().unwrap()
    };

    let test_cases = vec![
        (vec![false, false], false),
        (vec![false, true], false),
        (vec![true, false], false),
        (vec![true, true], true),
    ];

    test_circuit_correctness(circuit_builder, &test_cases);
}

/// Test: Chained AND gates (2 gates) - (a AND b) AND c
#[test]
fn test_chained_and_gates() {
    let circuit_builder = || {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_input();
        let b = builder.add_input();
        let c = builder.add_input();
        let ab = builder.add_and_gate(a, b);
        let abc = builder.add_and_gate(ab, c);
        builder.add_output(abc);
        builder.build().unwrap()
    };

    let test_cases = vec![
        (vec![false, false, false], false),
        (vec![false, false, true], false),
        (vec![false, true, false], false),
        (vec![false, true, true], false),
        (vec![true, false, false], false),
        (vec![true, false, true], false),
        (vec![true, true, false], false),
        (vec![true, true, true], true),
    ];

    test_circuit_correctness(circuit_builder, &test_cases);
}

/// Test: XOR then AND (1 gate) - (a XOR b) AND c
#[test]
fn test_xor_then_and() {
    let circuit_builder = || {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_input();
        let b = builder.add_input();
        let c = builder.add_input();
        let ab_xor = builder.add_xor_gate(a, b);
        let result = builder.add_and_gate(ab_xor, c);
        builder.add_output(result);
        builder.build().unwrap()
    };

    let test_cases = vec![
        (vec![false, false, false], false), // (0 XOR 0) AND 0 = 0
        (vec![false, false, true], false),  // (0 XOR 0) AND 1 = 0
        (vec![false, true, false], false),  // (0 XOR 1) AND 0 = 0
        (vec![false, true, true], true),    // (0 XOR 1) AND 1 = 1
        (vec![true, false, false], false),  // (1 XOR 0) AND 0 = 0
        (vec![true, false, true], true),    // (1 XOR 0) AND 1 = 1
        (vec![true, true, false], false),   // (1 XOR 1) AND 0 = 0
        (vec![true, true, true], false),    // (1 XOR 1) AND 1 = 0
    ];

    test_circuit_correctness(circuit_builder, &test_cases);
}

/// Test: AND, XOR, AND (2 gates) - ((a AND b) XOR c) AND d
#[test]
fn test_and_xor_and() {
    let circuit_builder = || {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_input();
        let b = builder.add_input();
        let c = builder.add_input();
        let d = builder.add_input();
        let ab = builder.add_and_gate(a, b);
        let ab_xor_c = builder.add_xor_gate(ab, c);
        let result = builder.add_and_gate(ab_xor_c, d);
        builder.add_output(result);
        builder.build().unwrap()
    };

    let test_cases = vec![
        (vec![false, false, false, false], false),
        (vec![false, false, false, true], false),
        (vec![false, false, true, false], false),
        (vec![false, false, true, true], true),
        (vec![false, true, false, false], false),
        (vec![false, true, false, true], false),
        (vec![false, true, true, false], false),
        (vec![false, true, true, true], true),
        (vec![true, false, false, false], false),
        (vec![true, false, false, true], false),
        (vec![true, false, true, false], false),
        (vec![true, false, true, true], true),
        (vec![true, true, false, false], false),
        (vec![true, true, false, true], true),
        (vec![true, true, true, false], false),
        (vec![true, true, true, true], false),
    ];

    test_circuit_correctness(circuit_builder, &test_cases);
}

/// Test: Four chained AND gates (4 gates)
#[test]
fn test_four_chained_and_gates() {
    let circuit_builder = || {
        let mut builder = CircuitBuilder::new();
        let a = builder.add_input();
        let b = builder.add_input();
        let c = builder.add_input();
        let d = builder.add_input();
        let ab = builder.add_and_gate(a, b);
        let cd = builder.add_and_gate(c, d);
        let abcd = builder.add_and_gate(ab, cd);
        builder.add_output(abcd);
        builder.build().unwrap()
    };

    // Only test a subset of the 16 combinations for speed
    let test_cases = vec![
        (vec![false, false, false, false], false),
        (vec![true, false, true, false], false),
        (vec![true, true, false, false], false),
        (vec![true, true, true, false], false),
        (vec![true, true, true, true], true),
    ];

    test_circuit_correctness(circuit_builder, &test_cases);
}

// ==============================================================================
// Large Circuit Tests (100+ AND gates)
//
// These tests verify correctness on realistic circuits
// ==============================================================================

/// Test: XOR-only circuit produces no encrypted gates
#[test]
fn test_xor_only_circuit() {
    let mut rng = StdRng::seed_from_u64(0);

    let circ = xor(8);
    assert_eq!(circ.and_count(), 0);

    let a = 1u8;
    let b = 2u8;
    let expected = a ^ b;

    let delta = Delta::random(&mut rng);

    let input_keys: Vec<Key> = (0..circ.inputs().len())
        .map(|_| {
            let block: Block = rng.random();
            block.into()
        })
        .collect();

    let input_bits: Vec<bool> = a.iter_lsb0().chain(b.iter_lsb0()).collect();

    // Garble
    let mut gb = Garbler::default();
    let mut gb_iter = gb
        .generate_batched(&circ, delta, &input_keys, &mut rng)
        .unwrap();

    let mut encrypted_gates = Vec::new();
    for batch in gb_iter.by_ref() {
        encrypted_gates.extend(batch.into_array());
    }

    assert_eq!(
        encrypted_gates.len(),
        0,
        "XOR-only circuit should produce no encrypted gates"
    );

    let GarblerOutput {
        outputs: output_labels,
    } = gb_iter.finish().unwrap();

    let delta_block = *delta.as_block();
    let input_macs: Vec<Mac> = input_keys
        .iter()
        .zip(&input_bits)
        .map(|(key, &bit)| {
            let key_block = *key.as_block();
            if bit {
                (key_block ^ delta_block).into()
            } else {
                key_block.into()
            }
        })
        .collect();

    // Evaluate
    let mut ev = Evaluator::default();
    let mut ev_consumer = ev.evaluate(&circ, &input_macs).unwrap();

    for gate in encrypted_gates {
        ev_consumer.next(gate);
    }

    let EvaluatorOutput {
        outputs: output_macs,
    } = ev_consumer.finish().unwrap();

    // Decode: check if mac equals true_label (false_label XOR delta)
    let output: u8 = u8::from_lsb0_iter(output_macs.into_iter().zip(&output_labels).map(
        |(mac, false_label)| {
            let true_label = Mac::from(*false_label.as_block() ^ delta_block);
            mac == true_label
        },
    ));

    assert_eq!(output, expected);
}

/// Test: AES128 circuit (6800 AND gates)
#[test]
fn test_aes128_circuit() {
    let mut rng = StdRng::seed_from_u64(0);

    let key = [69u8; 16];
    let msg = [42u8; 16];

    let expected: [u8; 16] = {
        let cipher = AesCipher::new_from_slice(&key).unwrap();
        let mut out = msg.into();
        cipher.encrypt_block(&mut out);
        out.into()
    };

    let delta = Delta::random(&mut rng);

    let input_keys: Vec<Key> = (0..AES128.inputs().len())
        .map(|_| {
            let block: Block = rng.random();
            block.into()
        })
        .collect();

    let input_bits: Vec<bool> = key.iter().copied().chain(msg).into_iter_lsb0().collect();

    // Garble
    let mut gb = Garbler::default();
    let mut gb_iter = gb
        .generate_batched(&AES128, delta, &input_keys, &mut rng)
        .unwrap();

    let mut encrypted_gates = Vec::new();
    for batch in gb_iter.by_ref() {
        encrypted_gates.extend(batch.into_array());
    }

    let GarblerOutput {
        outputs: output_labels,
    } = gb_iter.finish().unwrap();

    let delta_block = *delta.as_block();
    let input_macs: Vec<Mac> = input_keys
        .iter()
        .zip(&input_bits)
        .map(|(key, &bit)| {
            let key_block = *key.as_block();
            if bit {
                (key_block ^ delta_block).into()
            } else {
                key_block.into()
            }
        })
        .collect();

    // Evaluate
    let mut ev = Evaluator::default();
    let mut ev_consumer = ev.evaluate(&AES128, &input_macs).unwrap();

    for gate in encrypted_gates {
        ev_consumer.next(gate);
    }

    let EvaluatorOutput {
        outputs: output_macs,
    } = ev_consumer.finish().unwrap();

    // Decode: check if mac equals true_label (false_label XOR delta)
    let output: Vec<u8> = Vec::from_lsb0_iter(output_macs.into_iter().zip(&output_labels).map(
        |(mac, false_label)| {
            let true_label = Mac::from(*false_label.as_block() ^ delta_block);
            mac == true_label
        },
    ));

    assert_eq!(output, expected);
}

/// Test: AES128 with circuit reuse (preprocessed garbling)
#[test]
fn test_aes128_preprocessed() {
    let mut rng = StdRng::seed_from_u64(0);

    let key = [69u8; 16];
    let msg = [42u8; 16];

    let expected: [u8; 16] = {
        let cipher = AesCipher::new_from_slice(&key).unwrap();
        let mut out = msg.into();
        cipher.encrypt_block(&mut out);
        out.into()
    };

    let delta = Delta::random(&mut rng);

    let input_keys: Vec<Key> = (0..AES128.inputs().len())
        .map(|_| {
            let block: Block = rng.random();
            block.into()
        })
        .collect();

    let input_bits: Vec<bool> = key.iter().copied().chain(msg).into_iter_lsb0().collect();

    let mut gb = Garbler::default();
    let mut gb_iter = gb
        .generate_batched(&AES128, delta, &input_keys, &mut rng)
        .unwrap();

    // Collect (preprocess)
    let mut encrypted_gates = Vec::new();
    for batch in gb_iter.by_ref() {
        encrypted_gates.extend(batch.into_array());
    }

    let GarblerOutput {
        outputs: output_labels,
    } = gb_iter.finish().unwrap();

    let delta_block = *delta.as_block();
    let input_macs: Vec<Mac> = input_keys
        .iter()
        .zip(&input_bits)
        .map(|(key, &bit)| {
            let key_block = *key.as_block();
            if bit {
                (key_block ^ delta_block).into()
            } else {
                key_block.into()
            }
        })
        .collect();

    // Evaluate the same circuit twice using preprocessed gates
    for _ in 0..2 {
        let mut ev = Evaluator::default();
        let mut ev_consumer = ev.evaluate(&AES128, &input_macs).unwrap();

        for gate in &encrypted_gates {
            ev_consumer.next(*gate);
        }

        let EvaluatorOutput {
            outputs: output_macs,
        } = ev_consumer.finish().unwrap();

        let output: Vec<u8> = Vec::from_lsb0_iter(output_macs.iter().zip(&output_labels).map(
            |(mac, false_label)| {
                let true_label = Mac::from(*false_label.as_block() ^ delta_block);
                mac == &true_label
            },
        ));

        assert_eq!(output, expected);
    }
}
