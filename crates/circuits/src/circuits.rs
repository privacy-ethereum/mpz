//! Pre-built circuits for MPC.

use once_cell::sync::Lazy;
use std::sync::Arc;

use crate::{Circuit, CircuitBuilder};

/// Returns a wrapping adder circuit for `u8`.
///
/// `fn(u8, u8) -> u8`
pub fn adder_u8() -> Circuit {
    let mut builder = CircuitBuilder::new();

    let a: [_; 8] = std::array::from_fn(|_| builder.add_input());
    let b: [_; 8] = std::array::from_fn(|_| builder.add_input());

    let sum = crate::ops::wrapping_add(&mut builder, &a, &b);

    for node in sum {
        builder.add_output(node);
    }

    builder.build().unwrap()
}

/// Returns a circuit for XORing two arguments of the same size.
///
/// `fn(T, T) -> T`
pub fn xor(size: usize) -> Circuit {
    let mut builder = CircuitBuilder::new();

    let a = (0..size).map(|_| builder.add_input()).collect::<Vec<_>>();
    let b = (0..size).map(|_| builder.add_input()).collect::<Vec<_>>();

    for (a, b) in a.into_iter().zip(b) {
        let out = builder.add_xor_gate(a, b);
        builder.add_output(out);
    }

    builder.build().unwrap()
}

/// AES-128 circuit.
///
/// The circuit has the following signature:
///
/// `fn(key: [u8; 16], msg: [u8; 16]) -> [u8; 16]`
#[cfg(feature = "aes")]
pub static AES128: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../circuits/bin/aes_128.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

/// SHA-256 circuit.
///
/// The circuit has the following signature:
///
/// `fn(msg: [u8; 64], state: [u32; 8]) -> [u32; 8]`
#[cfg(feature = "sha2")]
pub static SHA256_COMPRESS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    let bytes = include_bytes!("../circuits/bin/sha256.bin");
    Arc::new(bincode::deserialize(bytes).unwrap())
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate;

    static SHA2_INITIAL_STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[test]
    fn test_xor() {
        let a = [42u8; 16];
        let b = [69u8; 16];
        let xor = xor(128);
        let output: [u8; 16] = evaluate!(xor, a, b).unwrap();
        let expected = std::array::from_fn(|i| a[i] ^ b[i]);
        assert_eq!(output, expected);
    }

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
}
