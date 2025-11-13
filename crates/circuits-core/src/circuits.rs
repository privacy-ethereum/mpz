//! Circuits for MPC.

pub mod blake3;

use crate::{
    Circuit, CircuitBuilder, Feed, Node,
    ops::{mul_by_10, wrapping_add},
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

/// Builds a circuit that converts the big-endian decimal digits of an integer
/// into its binary representation in least-significant-bit-first (lsb0) order.
///
/// # Arguments
///
/// * `size` — The number of decimal digits in the input integer.
///
/// # Example
///
/// The decimal integer `65000` should be provided as `[6u8, 5, 0, 0, 0]`.
/// The resulting output will contain 16 bits representing the value
/// `0001 0111 1011 1111` in lsb0 order.
///
/// # Warning
///
/// Each input element must be a valid decimal digit in the range `0..=9`.
/// Supplying any value greater than `9` will produce a meaningless result,
/// as no validation is performed within the circuit.
pub fn int_to_bits(size: usize) -> Circuit {
    assert!(size > 1);

    let mut builder = CircuitBuilder::new();

    let digits: Vec<_> = (0..size * 8).map(|_| builder.add_input()).collect();
    let mut digits = digits.chunks(8);

    let mut acc: Vec<Node<Feed>> = digits.next().unwrap().try_into().unwrap();

    // Workaround: we can't have a const wire in the circuit output.
    let zero = builder.add_xor_gate(acc[0], acc[0]);

    // Shift right and add.
    for _ in 1..size {
        let mut res = mul_by_10(&mut builder, &acc);
        let mut digit = digits.next().unwrap().to_vec();

        // Pad the digit bits to the size of accumulator.
        for _ in 0..res.len() - 8 {
            digit.push(zero);
        }

        // Pad both summands to prevent overflow.
        res.push(zero);
        digit.push(zero);

        acc = wrapping_add(&mut builder, &res, &digit);
    }

    for feed in acc {
        builder.add_output(feed);
    }

    builder.build().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate;
    use num_bigint::BigUint;
    use num_traits::Zero;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

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
    fn test_decimal_to_bits() {
        const MAX_DIGITS: usize = 4;
        let mut rng = ChaCha8Rng::seed_from_u64(1u64);

        // First, test every decimal integer of the given digit count.
        for count in 2..=MAX_DIGITS {
            let circ = int_to_bits(count);

            for input in 10u32.pow((count - 1) as u32)..10u32.pow(count as u32) {
                let digits: Vec<u8> = input
                    .to_string()
                    .chars()
                    .map(|c| c.to_digit(10).unwrap() as u8)
                    .collect();

                let output: u32 = evaluate!(circ, digits).unwrap();
                assert_eq!(output, input);
            }
        }

        fn digits_to_biguint(digs: &[u8]) -> BigUint {
            digs.iter().fold(BigUint::zero(), |acc, &d| acc * 10u32 + d)
        }

        // Then, test random decimal integers of various digit counts.
        for count in MAX_DIGITS..50 {
            let circ = int_to_bits(count);

            let digits: Vec<u8> = (0..count).map(|_| rng.random_range(0..10)).collect();
            let output: Vec<u8> = evaluate!(circ, digits).unwrap();

            assert_eq!(digits_to_biguint(&digits), BigUint::from_bytes_le(&output));
        }
    }
}
