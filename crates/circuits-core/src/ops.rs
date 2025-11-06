//! Binary operations.

use crate::{
    CircuitBuilder,
    components::{Feed, Node},
};

/// Binary full-adder.
pub fn full_adder(
    builder: &mut CircuitBuilder,
    a: Node<Feed>,
    b: Node<Feed>,
    c_in: Node<Feed>,
) -> (Node<Feed>, Node<Feed>) {
    // SUM = A ⊕ B ⊕ C_IN
    let a_b = builder.add_xor_gate(a, b);
    let sum = builder.add_xor_gate(a_b, c_in);

    // C_OUT = C_IN ⊕ ((A ⊕ C_IN) ^ (B ⊕ C_IN))
    let a_c_in = builder.add_xor_gate(a, c_in);
    let b_c_in = builder.add_xor_gate(b, c_in);
    let and = builder.add_and_gate(a_c_in, b_c_in);
    let c_out = builder.add_xor_gate(and, c_in);

    (sum, c_out)
}

/// Binary full-adder which does not compute the carry-out bit.
pub fn full_adder_no_carry_out(
    builder: &mut CircuitBuilder,
    a: Node<Feed>,
    b: Node<Feed>,
    c_in: Node<Feed>,
) -> Node<Feed> {
    // SUM = A ⊕ B ⊕ C_IN
    let a_b = builder.add_xor_gate(a, b);
    builder.add_xor_gate(a_b, c_in)
}

/// Binary half-adder.
pub fn half_adder(
    builder: &mut CircuitBuilder,
    a: Node<Feed>,
    b: Node<Feed>,
) -> (Node<Feed>, Node<Feed>) {
    // SUM = A ⊕ B
    let sum = builder.add_xor_gate(a, b);
    // C_OUT = A ^ B
    let c_out = builder.add_and_gate(a, b);

    (sum, c_out)
}

/// Add two nbit values together, wrapping on overflow.
pub fn wrapping_add(
    builder: &mut CircuitBuilder,
    a: &[Node<Feed>],
    b: &[Node<Feed>],
) -> Vec<Node<Feed>> {
    assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut c_out = Node::new(0);
    a.iter()
        .zip(b)
        .enumerate()
        .map(|(n, (a, b))| {
            if n == 0 {
                // no carry in
                let (sum_0, c_out_0) = half_adder(builder, *a, *b);
                c_out = c_out_0;
                sum_0
            } else if n < len - 1 {
                let (sum_n, c_out_n) = full_adder(builder, *a, *b, c_out);
                c_out = c_out_n;
                sum_n
            } else {
                // On the last iteration we don't compute the carry-out bit.
                full_adder_no_carry_out(builder, *a, *b, c_out)
            }
        })
        .collect()
}

/// Subtract two nbit values, wrapping on underflow.
///
/// Returns the result and the bit indicating whether underflow occurred.
pub fn wrapping_sub(
    builder: &mut CircuitBuilder,
    a: &[Node<Feed>],
    b: &[Node<Feed>],
) -> (Vec<Node<Feed>>, Node<Feed>) {
    assert_eq!(a.len(), b.len());

    // invert b
    let b_inv = b
        .iter()
        .map(|b| builder.add_inv_gate(*b))
        .collect::<Vec<_>>();

    // Set first b_in to 1, which adds 1 to b_inv.
    let mut b_out = Node::new(1);

    let diff = a
        .iter()
        .zip(b_inv)
        .map(|(a, b_inv)| {
            let (diff_n, b_out_n) = full_adder(builder, *a, b_inv, b_out);
            b_out = b_out_n;
            diff_n
        })
        .collect();

    // underflow occurred if b_out is 0
    let underflow = builder.add_inv_gate(b_out);

    (diff, underflow)
}

/// Add two numbers modulo a constant modulus.
///
/// This circuit assumes that the summands are in the range [0, modulus).
///
/// # Returns
///
/// (a + b) % modulus
pub fn add_mod(
    builder: &mut CircuitBuilder,
    a: &[Node<Feed>],
    b: &[Node<Feed>],
    modulus: &[Node<Feed>],
) -> Vec<Node<Feed>> {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), modulus.len());

    // Tack on an extra bit to absorb overflow
    let mut a = a.to_vec();
    a.push(builder.get_const_zero());
    let mut b = b.to_vec();
    b.push(builder.get_const_zero());
    let mut modulus = modulus.to_vec();
    modulus.push(builder.get_const_zero());

    let sum = wrapping_add(builder, &a, &b);

    let (rem, underflow) = wrapping_sub(builder, &sum, &modulus);

    // if sum < modulus { sum } else { sum - modulus }
    let sum_reduced = switch(builder, &rem, &sum, underflow);

    // Pop off the extra bit
    sum_reduced[..sum_reduced.len() - 1].to_vec()
}

/// Switch between two nbit values.
///
/// If `toggle` is 0, the result is `a`, otherwise it is `b`.
pub fn switch(
    builder: &mut CircuitBuilder,
    a: &[Node<Feed>],
    b: &[Node<Feed>],
    toggle: Node<Feed>,
) -> Vec<Node<Feed>> {
    assert_eq!(a.len(), b.len());

    let not_toggle = builder.add_inv_gate(toggle);

    a.iter()
        .zip(b)
        .map(|(a, b)| {
            let a_and_not_toggle = builder.add_and_gate(*a, not_toggle);
            let b_and_toggle = builder.add_and_gate(*b, toggle);
            builder.add_xor_gate(a_and_not_toggle, b_and_toggle)
        })
        .collect()
}

/// Bitwise XOR of two nbit values.
pub fn xor<const N: usize>(
    builder: &mut CircuitBuilder,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> [Node<Feed>; N] {
    std::array::from_fn(|n| builder.add_xor_gate(a[n], b[n]))
}

/// Bitwise AND of two nbit values.
pub fn and<const N: usize>(
    builder: &mut CircuitBuilder,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> [Node<Feed>; N] {
    std::array::from_fn(|n| builder.add_and_gate(a[n], b[n]))
}

/// Bitwise OR of two nbit values.
pub fn or<const N: usize>(
    builder: &mut CircuitBuilder,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> [Node<Feed>; N] {
    std::array::from_fn(|n| {
        // OR = (A ⊕ B) ⊕ (A ^ B)
        let a_xor_b = builder.add_xor_gate(a[n], b[n]);
        let a_and_b = builder.add_and_gate(a[n], b[n]);

        builder.add_xor_gate(a_xor_b, a_and_b)
    })
}

/// Bitwise NOT of an nbit value.
pub fn inv<const N: usize>(builder: &mut CircuitBuilder, a: [Node<Feed>; N]) -> [Node<Feed>; N] {
    std::array::from_fn(|n| builder.add_inv_gate(a[n]))
}

#[cfg(test)]
mod tests {
    use std::array::from_fn;

    use crate::evaluate;

    use super::*;

    #[test]
    fn test_wrapping_add() {
        let mut builder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());
        let b: [_; 8] = from_fn(|_| builder.add_input());

        let sum = wrapping_add(&mut builder, &a, &b);

        for node in sum {
            builder.add_output(node);
        }

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected_sum = a.wrapping_add(b);

                let sum: u8 = evaluate!(circ, a, b).unwrap();

                assert_eq!(sum, expected_sum);
            }
        }
    }

    #[test]
    fn test_wrapping_sub() {
        let mut builder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());
        let b: [_; 8] = from_fn(|_| builder.add_input());

        let (rem, borrow) = wrapping_sub(&mut builder, &a, &b);

        for node in rem {
            builder.add_output(node);
        }
        builder.add_output(borrow);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected_rem = a.wrapping_sub(b);
                let expected_underflow = a < b;

                let (rem, underflow): (u8, bool) = evaluate!(circ, a, b).unwrap();

                assert_eq!(rem, expected_rem);
                assert_eq!(underflow, expected_underflow);
            }
        }
    }

    #[test]
    fn test_add_mod() {
        let mut builder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());
        let b: [_; 8] = from_fn(|_| builder.add_input());
        let modulus: [_; 8] = from_fn(|_| builder.add_input());

        let sum = add_mod(&mut builder, &a, &b, &modulus);

        for node in sum {
            builder.add_output(node);
        }

        let circ = builder.build().unwrap();

        let modulus = 251u8;
        for a in 0u8..127 {
            for b in 0u8..127 {
                let expected_sum = (a + b) % modulus;
                let sum: u8 = evaluate!(&circ, a, b, modulus).unwrap();
                assert_eq!(sum, expected_sum);
            }
        }
    }

    #[test]
    fn test_switch() {
        let mut builder = CircuitBuilder::new();

        let a: [_; 8] = std::array::from_fn(|_| builder.add_input());
        let b: [_; 8] = std::array::from_fn(|_| builder.add_input());
        let toggle = builder.add_input();

        let out = switch(&mut builder, &a, &b, toggle);

        for node in out {
            builder.add_output(node);
        }

        let circ = builder.build().unwrap();

        let a = 42u8;
        let b = 69u8;

        let out: u8 = evaluate!(circ, a, b, false).unwrap();
        assert_eq!(out, a);

        let out: u8 = evaluate!(circ, a, b, true).unwrap();
        assert_eq!(out, b);
    }
}
