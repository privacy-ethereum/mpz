//! Pre-built circuits for MPC.

use mpz_circuits::Circuit;
use once_cell::sync::Lazy;
use std::sync::Arc;

/// AES-128 circuit.
///
/// The circuit has the following signature:
///
/// `fn(key: [u8; 16], msg: [u8; 16]) -> [u8; 16]`
#[cfg(feature = "aes")]
pub static AES128: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../../circuits/bin/aes_128.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// AES-128 key schedule circuit.
///
/// The circuit has the following signature:
///
/// `fn(key: [u8; 16]) -> [u8; 176]`
///
/// The output is the key schedule: 11 round keys, 16 bytes each.
#[cfg(feature = "aes")]
pub static AES128_KS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../../circuits/bin/aes_128_ks.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// AES-128 post key schedule encryption circuit.
///
/// The circuit has the following signature:
///
/// `fn(key_schedule: [u8; 176], msg: [u8; 16]) -> [u8; 16]`
///
/// `key_schedule` is 11 round keys, 16 bytes each.
#[cfg(feature = "aes")]
pub static AES128_POST_KS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../../circuits/bin/aes_128_post_ks.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// SHA-256 circuit.
///
/// The circuit has the following signature:
///
/// `fn(msg: [u8; 64], state: [u32; 8]) -> [u32; 8]`
#[cfg(feature = "sha2")]
pub static SHA256_COMPRESS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../../circuits/bin/sha256.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// Blake3 compression circuit.
///
/// The circuit has the following signature:
///
/// `fn(msg: [u32; 16], state: [u32; 16]) -> [u32; 16]`
#[cfg(feature = "blake3")]
pub static BLAKE3_COMPRESS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../../circuits/bin/blake3.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuits::evaluate;

    static SHA2_INITIAL_STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[test]
    #[cfg(feature = "aes")]
    fn test_aes128() {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        use rand::{Rng, SeedableRng, rngs::StdRng};

        fn aes_128(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
            use aes::Aes128;

            let aes = Aes128::new_from_slice(&key).unwrap();
            let mut ciphertext = msg.into();
            aes.encrypt_block(&mut ciphertext);
            ciphertext.into()
        }

        let mut rng = StdRng::seed_from_u64(0);

        let key: [u8; 16] = rng.random();
        let msg: [u8; 16] = rng.random();
        let ciphertext: [u8; 16] = evaluate!(AES128, key, msg).unwrap();
        let expected = aes_128(key, msg);
        assert_eq!(ciphertext, expected);
    }

    #[test]
    #[cfg(feature = "aes")]
    fn test_aes128_two_stage() {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        use rand::{Rng, SeedableRng, rngs::StdRng};

        fn aes_128(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
            use aes::Aes128;

            let aes = Aes128::new_from_slice(&key).unwrap();
            let mut ciphertext = msg.into();
            aes.encrypt_block(&mut ciphertext);
            ciphertext.into()
        }

        let mut rng = StdRng::seed_from_u64(0);

        let key: [u8; 16] = rng.random();
        let msg: [u8; 16] = rng.random();

        let ks: [u8; 176] = evaluate!(AES128_KS, key).unwrap();
        let ciphertext: [u8; 16] = evaluate!(AES128_POST_KS, ks, msg).unwrap();

        let expected: [u8; 16] = aes_128(key, msg);
        assert_eq!(ciphertext, expected);
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_sha256_compress() {
        fn sha256_compress(msg: [u8; 64], state: [u32; 8]) -> [u32; 8] {
            let mut state = state;
            sha2::compress256(&mut state, &[msg.into()]);
            state
        }

        let msg = [69u8; 64];
        let output: [u32; 8] = evaluate!(SHA256_COMPRESS, msg, SHA2_INITIAL_STATE).unwrap();
        let expected = sha256_compress(msg, SHA2_INITIAL_STATE);
        assert_eq!(output, expected);
    }

    #[test]
    #[cfg(feature = "blake3")]
    fn test_blake3() {
        let iv = [1u32; 16];
        let msg = [1u32; 16];
        // Output obtained from `test_blake3_compress`
        // in crates/circuits/src/circuits/blake3.rs
        let expected_output: [u32; 16] = [
            3007729955, 3007729955, 3007729955, 3007729955, 34758502, 34758502, 34758502, 34758502,
            4028310545, 4028310545, 4028310545, 4028310545, 2799904522, 2799904522, 2799904522,
            2799904522,
        ];

        let output: [u32; 16] = evaluate!(BLAKE3_COMPRESS, msg, iv).unwrap();

        assert_eq!(output, expected_output);
    }
}
