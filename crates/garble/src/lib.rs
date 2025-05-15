//! Garbled circuit VM implementations.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod evaluator;
pub(crate) mod garbler;
pub(crate) mod auth_gen;
pub(crate) mod auth_eval;
pub mod protocol;
pub(crate) mod store;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use mpz_circuits::circuits::AES128;
    use itybity::{FromBitIterator, IntoBitIterator, ToBits};
    use mpz_common::context::test_st_context;
    use mpz_memory_core::correlated::{Delta, Key, Mac};
    use mpz_garble_core::{AuthGenOutput, AuthEvalOutput};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use aes::{
        Aes128,
        cipher::{BlockCipherEncrypt, KeyInit},
    };
    use mpz_garble_core::{fpre::bit_shares_from_cot, SSP};
    use super::*;

    #[tokio::test]
    async fn test_semihonest_core() {

        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let circ = &**AES128;
        
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

        // Run garbler and evaluator concurrently
        let (garbler_output, evaluator_output) = tokio::join!(
            async {
                garbler::generate(&mut ctx_0, Arc::new(circ.clone()), delta, &input_keys).await
            },
            async {
                evaluator::evaluate(&mut ctx_1, Arc::new(circ.clone()), &input_macs).await
            }
        );

        let output_keys = garbler_output.unwrap().outputs;
        let output_macs = evaluator_output.unwrap().outputs;

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

    #[tokio::test]
    async fn test_auth_core() {
        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let circ = &**AES128;
        
        let mut rng = StdRng::seed_from_u64(0);

        let key = [69u8; 16];
        let msg = [42u8; 16];

        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut out = msg.into();
            cipher.encrypt_block(&mut out);
            out.into()
        };

        let delta_a = Delta::random(&mut rng).set_lsb(true);
        let delta_b = Delta::random(&mut rng).set_lsb(false);

        // Calculate total number of shares needed
        let bucket_size = (SSP as f64 / (circ.and_count() as f64).log2()).ceil() as usize;
        let num_input_shares = circ.inputs().len();
        let num_and_shares = circ.and_count()*(3*bucket_size+1);
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

        let input_keys = (0..circ.inputs().len())
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

        // Run garbler and evaluator concurrently
        let (garbler_output, evaluator_output) = tokio::join!(
            async {
                auth_gen::generate(&mut ctx_0, Arc::new(circ.clone()), delta_a, &input_keys, &gen_input_shares, &gen_and_shares).await
            },
            async {
                auth_eval::evaluate(&mut ctx_1, Arc::new(circ.clone()), delta_b, &input_macs, masked_inputs, &eval_input_shares, &eval_and_shares).await
            }
        );

        let AuthEvalOutput {
            output_labels: eval_output_labels,
            output_auth_bits: eval_output_auth_bits,
            auth_hash: eval_auth_hash,
            masked_output_values,
            masked_values: _masked_values,
        } = evaluator_output.unwrap();

        let AuthGenOutput {
            output_labels: gen_output_labels,
            output_auth_bits: gen_output_auth_bits,
            auth_hash: gen_auth_hash,
        } = garbler_output.unwrap();

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
