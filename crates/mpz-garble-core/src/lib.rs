//! Core components used to implement garbled circuit protocols
//!
//! This module implements "half-gate" garbled circuits from the [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) paper.
//!
//! # Example
//!
//! ```
//! use mpz_circuits::circuits::AES128;
//! use mpz_garble_core::{
//!     Generator, Evaluator, ChaChaEncoder, Encoder, GeneratorOutput, EvaluatorOutput
//! };
//!
//!
//! let encoder = ChaChaEncoder::new([0u8; 32]);
//! let encoded_key = encoder.encode::<[u8; 16]>(0);
//! let encoded_plaintext = encoder.encode::<[u8; 16]>(1);
//!
//! let key = b"super secret key";
//! let plaintext = b"super secret msg";
//!
//! let active_key = encoded_key.select(*key).unwrap();
//! let active_plaintext = encoded_plaintext.select(*plaintext).unwrap();
//!
//! let mut gen = Generator::default();
//! let mut ev = Evaluator::default();
//!
//! let mut gen_iter = gen
//!    .generate_batched(&AES128, encoder.delta(), vec![encoded_key, encoded_plaintext]).unwrap();
//! let mut ev_consumer = ev.evaluate_batched(&AES128, vec![active_key, active_plaintext]).unwrap();
//!
//! for batch in gen_iter.by_ref() {
//!    ev_consumer.next(batch);
//! }
//!
//! let GeneratorOutput { outputs: encoded_outputs, .. } = gen_iter.finish().unwrap();
//! let encoded_ciphertext = encoded_outputs[0].clone();
//! let ciphertext_decoding = encoded_ciphertext.decoding();
//!
//! let EvaluatorOutput { outputs: active_outputs, .. } = ev_consumer.finish().unwrap();
//! let active_ciphertext = active_outputs[0].clone();
//! let ciphertext: [u8; 16] =
//!     active_ciphertext.decode(&ciphertext_decoding).unwrap().try_into().unwrap();
//!
//! println!("'{plaintext:?} AES encrypted with key '{key:?}' is '{ciphertext:?}'");
//! ```

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]

pub(crate) mod circuit;
pub mod encoding;
mod evaluator;
mod generator;

pub use circuit::{EncryptedGate, EncryptedGateBatch, GarbledCircuit};
pub use encoding::{
    state as encoding_state, ChaChaEncoder, Decoding, Delta, Encode, EncodedValue, Encoder,
    EncodingCommitment, EqualityCheck, Label, ValueError,
};
pub use evaluator::{
    EncryptedGateBatchConsumer, EncryptedGateConsumer, Evaluator, EvaluatorError, EvaluatorOutput,
};
pub use generator::{
    EncryptedGateBatchIter, EncryptedGateIter, Generator, GeneratorError, GeneratorOutput,
};

const KB: usize = 1024;
const BYTES_PER_GATE: usize = 32;

/// Maximum size of a batch in bytes.
const MAX_BATCH_SIZE: usize = 4 * KB;

/// Default amount of encrypted gates per batch.
///
/// Batches are stack allocated, so we will limit the size to `MAX_BATCH_SIZE`.
///
/// Additionally, because the size of each batch is static, if a circuit is smaller than a batch
/// we will be wasting some bandwidth sending empty bytes. This puts an upper limit on that
/// waste.
pub(crate) const DEFAULT_BATCH_SIZE: usize = MAX_BATCH_SIZE / BYTES_PER_GATE;

#[cfg(test)]
mod tests {
    use aes::{
        cipher::{BlockEncrypt, KeyInit},
        Aes128,
    };
    use mpz_circuits::{circuits::AES128, types::Value, CircuitBuilder};
    use mpz_core::aes::FIXED_KEY_AES;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use super::*;

    #[test]
    fn test_and_gate() {
        use crate::{evaluator as ev, generator as gen};

        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let cipher = &(*FIXED_KEY_AES);

        let delta = Delta::random(&mut rng);
        let x_0 = Label::random(&mut rng);
        let x_1 = x_0 ^ delta;
        let y_0 = Label::random(&mut rng);
        let y_1 = y_0 ^ delta;
        let gid: usize = 1;

        let (z_0, encrypted_gate) = gen::and_gate(cipher, &x_0, &y_0, &delta, gid);
        let z_1 = z_0 ^ delta;

        assert_eq!(ev::and_gate(cipher, &x_0, &y_0, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_0, &y_1, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_1, &y_0, &encrypted_gate, gid), z_0);
        assert_eq!(ev::and_gate(cipher, &x_1, &y_1, &encrypted_gate, gid), z_1);
    }

    #[test]
    fn test_garble() {
        let encoder = ChaChaEncoder::new([0; 32]);

        let key = [69u8; 16];
        let msg = [42u8; 16];

        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut out = msg.into();
            cipher.encrypt_block(&mut out);
            out.into()
        };

        let full_inputs: Vec<EncodedValue<encoding_state::Full>> = AES128
            .inputs()
            .iter()
            .map(|input| encoder.encode_by_type(0, &input.value_type()))
            .collect();

        let active_inputs: Vec<EncodedValue<encoding_state::Active>> = vec![
            full_inputs[0].clone().select(key).unwrap(),
            full_inputs[1].clone().select(msg).unwrap(),
        ];

        let mut gen = Generator::default();
        let mut ev = Evaluator::default();

        let mut gen_iter = gen
            .generate_batched(&AES128, encoder.delta(), full_inputs)
            .unwrap();
        let mut ev_consumer = ev.evaluate_batched(&AES128, active_inputs).unwrap();

        gen_iter.enable_hasher();
        ev_consumer.enable_hasher();

        for batch in gen_iter.by_ref() {
            ev_consumer.next(batch);
        }

        let GeneratorOutput {
            outputs: full_outputs,
            hash: gen_hash,
        } = gen_iter.finish().unwrap();
        let EvaluatorOutput {
            outputs: active_outputs,
            hash: ev_hash,
        } = ev_consumer.finish().unwrap();

        let outputs: Vec<Value> = active_outputs
            .iter()
            .zip(full_outputs)
            .map(|(active_output, full_output)| {
                full_output.commit().verify(active_output).unwrap();
                active_output.decode(&full_output.decoding()).unwrap()
            })
            .collect();

        let actual: [u8; 16] = outputs[0].clone().try_into().unwrap();

        assert_eq!(actual, expected);
        assert_eq!(gen_hash, ev_hash);
    }

    // Tests garbling a circuit with no AND gates
    #[test]
    fn test_garble_no_and() {
        let encoder = ChaChaEncoder::new([0; 32]);

        let builder = CircuitBuilder::new();
        let a = builder.add_input::<u8>();
        let b = builder.add_input::<u8>();
        let c = a ^ b;
        builder.add_output(c);
        let circ = builder.build().unwrap();
        assert_eq!(circ.and_count(), 0);

        let mut gen = Generator::default();
        let mut ev = Evaluator::default();

        let a = 1u8;
        let b = 2u8;

        let full_inputs: Vec<EncodedValue<encoding_state::Full>> = circ
            .inputs()
            .iter()
            .map(|input| encoder.encode_by_type(0, &input.value_type()))
            .collect();

        let active_inputs: Vec<EncodedValue<encoding_state::Active>> = vec![
            full_inputs[0].clone().select(a).unwrap(),
            full_inputs[1].clone().select(b).unwrap(),
        ];

        let mut gen_iter = gen
            .generate_batched(&circ, encoder.delta(), full_inputs)
            .unwrap();
        let mut ev_consumer = ev.evaluate_batched(&circ, active_inputs).unwrap();

        gen_iter.enable_hasher();
        ev_consumer.enable_hasher();

        for batch in gen_iter.by_ref() {
            ev_consumer.next(batch);
        }

        let GeneratorOutput {
            outputs: full_outputs,
            hash: gen_hash,
        } = gen_iter.finish().unwrap();
        let EvaluatorOutput {
            outputs: active_outputs,
            hash: ev_hash,
        } = ev_consumer.finish().unwrap();

        let outputs: Vec<Value> = active_outputs
            .iter()
            .zip(full_outputs)
            .map(|(active_output, full_output)| {
                full_output.commit().verify(active_output).unwrap();
                active_output.decode(&full_output.decoding()).unwrap()
            })
            .collect();

        let actual: u8 = outputs[0].clone().try_into().unwrap();

        assert_eq!(actual, a ^ b);
        assert_eq!(gen_hash, ev_hash);
    }
}
