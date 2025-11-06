//! Circuits for MPC.

pub mod blake3;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate;

    #[test]
    fn test_xor() {
        let a = [42u8; 16];
        let b = [69u8; 16];
        let xor = xor(128);
        let output: [u8; 16] = evaluate!(xor, a, b).unwrap();
        let expected = std::array::from_fn(|i| a[i] ^ b[i]);
        assert_eq!(output, expected);
    }
}
