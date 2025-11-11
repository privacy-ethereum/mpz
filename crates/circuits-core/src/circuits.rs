//! Circuits for MPC.

pub mod blake3;

use crate::{
    Circuit, CircuitBuilder, Feed, Node,
    ops::{all, eq, inv},
};

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

/// Returns a circuit for asserting that a u8 is not present in the source
/// of the given byte `size`.
pub fn not_included_u8(size: usize) -> Circuit {
    assert!(size > 0);

    let mut builder = CircuitBuilder::new();

    let source = (0..size * 8)
        .map(|_| builder.add_input())
        .collect::<Vec<_>>();
    let needle: [Node<Feed>; 8] = (0..8)
        .map(|_| builder.add_input())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let not_eq = source
        .chunks(8)
        .flat_map(|chunk| {
            let eq = eq(
                &mut builder,
                chunk.try_into().expect("chunk length is 8"),
                needle,
            );
            inv(&mut builder, [eq])
        })
        .collect::<Vec<_>>();

    // All bytes are not equal to the needle.
    let out = all(&mut builder, &not_eq);
    builder.add_output(out);

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
    #[test]
    fn test_not_included_u8() {
        let needle = 5u8;
        let haystack = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let circ = not_included_u8(haystack.len());

        let output: bool = evaluate!(circ, haystack, needle).unwrap();
        assert_eq!(output, false);

        let output: bool = evaluate!(circ, haystack, 10u8).unwrap();
        assert_eq!(output, true);
    }
}
