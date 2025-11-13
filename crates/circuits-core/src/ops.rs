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

/// Returns true if two nbit values are equal.
pub fn eq<const N: usize>(
    builder: &mut CircuitBuilder,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> Node<Feed> {
    let a_xor_b = xor(builder, a, b);
    eq_zero(builder, a_xor_b)
}

/// Returns true if two nbit values are not equal.
pub fn neq<const N: usize>(
    builder: &mut CircuitBuilder,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> Node<Feed> {
    let a_xor_b = xor(builder, a, b);
    let eq = eq_zero(builder, a_xor_b);
    builder.add_inv_gate(eq)
}

/// Returns true if an nbit value equals zero.
pub fn eq_zero<const N: usize>(builder: &mut CircuitBuilder, a: [Node<Feed>; N]) -> Node<Feed> {
    assert!(!a.is_empty());

    let inv = inv(builder, a);

    let mut product = inv[0];
    for i in 1..N {
        product = builder.add_and_gate(product, inv[i]);
    }

    product
}

/// Returns true if lhs < rhs.
///
/// Both arguments are a lsb0 bit representations of an integer.
pub fn lt<const N: usize>(
    builder: &mut CircuitBuilder,
    lhs: [Node<Feed>; N],
    rhs: [Node<Feed>; N],
) -> Node<Feed> {
    assert!(!lhs.is_empty());

    let (lt, _) = lt_eq_core(builder, lhs, rhs);
    lt
}

/// Returns true if lhs <= rhs.
///
/// Both arguments are a lsb0 bit representations of an integer.
pub fn lte<const N: usize>(
    builder: &mut CircuitBuilder,
    lhs: [Node<Feed>; N],
    rhs: [Node<Feed>; N],
) -> Node<Feed> {
    assert!(!lhs.is_empty());

    let (lt, eq) = lt_eq_core(builder, lhs, rhs);

    any(builder, &[lt, eq])
}

/// Returns true if lhs > rhs.
///
/// Both arguments are a lsb0 bit representations of an integer.
pub fn gt<const N: usize>(
    builder: &mut CircuitBuilder,
    lhs: [Node<Feed>; N],
    rhs: [Node<Feed>; N],
) -> Node<Feed> {
    assert!(!lhs.is_empty());

    let (gt, _) = lt_eq_core(builder, rhs, lhs);
    gt
}

/// Returns true if lhs >= rhs.
///
/// Both arguments are a lsb0 bit representations of an integer.
pub fn gte<const N: usize>(
    builder: &mut CircuitBuilder,
    lhs: [Node<Feed>; N],
    rhs: [Node<Feed>; N],
) -> Node<Feed> {
    assert!(!lhs.is_empty());

    let (gt, eq) = lt_eq_core(builder, rhs, lhs);

    any(builder, &[gt, eq])
}

/// Internal: scan MSB→LSB once and return:
/// - lt: true iff lhs < rhs
/// - eq: true iff lhs == rhs
fn lt_eq_core<const N: usize>(
    builder: &mut CircuitBuilder,
    lhs: [Node<Feed>; N],
    rhs: [Node<Feed>; N],
) -> (Node<Feed>, Node<Feed>) {
    assert!(!lhs.is_empty());

    // Tracks whether all higher bits seen so far are equal.
    let mut eq = builder.get_const_one();

    // For each bit position, contains a signal whether the lhs < rhs
    // difference starts at that bit.
    let mut starts_here = Vec::new();

    // Scan for bit difference starting from MSB.
    for (bit_l, bit_r) in lhs.into_iter().rev().zip(rhs.into_iter().rev()) {
        // Check condition bit_l == 0 and bit_r == 1.
        let not_l = builder.add_inv_gate(bit_l);
        let condition = builder.add_and_gate(not_l, bit_r);

        // lhs < rhs starts at this bit position iff higher bits are equal and
        // the above condition holds.
        starts_here.push(builder.add_and_gate(eq, condition));

        // Update the eq value.
        let diff = builder.add_xor_gate(bit_l, bit_r);
        let not_diff = builder.add_inv_gate(diff);
        eq = builder.add_and_gate(eq, not_diff);
    }

    let is_less = any(builder, &starts_here);
    (is_less, eq)
}

/// Returns true if all input nodes evaluate to true.
pub fn all(builder: &mut CircuitBuilder, inputs: &[Node<Feed>]) -> Node<Feed> {
    assert!(!inputs.is_empty());

    let mut acc = inputs[0];
    for &bit in &inputs[1..] {
        let res = and(builder, [acc], [bit]);
        acc = res[0];
    }
    acc
}

/// Returns true if any input node evaluates to true.
pub fn any(builder: &mut CircuitBuilder, inputs: &[Node<Feed>]) -> Node<Feed> {
    assert!(!inputs.is_empty());

    let mut acc = inputs[0];
    for &x in &inputs[1..] {
        let res = or(builder, [acc], [x]);
        acc = res[0];
    }
    acc
}

/// Given a value's lsb0 bit representation, multiply the value by 10.
// x >> 3 + x >> 1 == 8x + 2x
pub fn mul_by_10(builder: &mut CircuitBuilder, x: &[Node<Feed>]) -> Vec<Node<Feed>> {
    assert!(x.len() > 0);

    // Workaround: we can't have a const wire in the circuit output.
    let zero = builder.add_xor_gate(x[0], x[0]);

    // Shift right and pad to avoid overflow when adding.
    let shift_by_3 = [vec![zero; 3], x.to_vec(), vec![zero; 1]].concat();

    // Shift right and pad to the length of the above summand.
    let shift_by_1 = [vec![zero; 1], x.to_vec(), vec![zero; 3]].concat();

    wrapping_add(builder, &shift_by_3, &shift_by_1)
        .try_into()
        .expect("no overflow")
}

#[cfg(test)]
mod tests {
    use std::array::from_fn;

    use itybity::{FromBitIterator, IntoBitIterator, IntoBits};

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
        for a in 0u8..modulus - 10 {
            for b in 0u8..modulus - 10 {
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

    #[test]
    fn test_eq() {
        let mut builder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());
        let b: [_; 8] = from_fn(|_| builder.add_input());

        let is_eq = eq(&mut builder, a, b);
        builder.add_output(is_eq);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected = a == b;
                let is_eq: bool = evaluate!(&circ, a, b).unwrap();
                assert_eq!(is_eq, expected);
            }
        }
    }

    #[test]
    fn test_eq_zero() {
        let mut builder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());

        let is_eq = eq_zero(&mut builder, a);
        builder.add_output(is_eq);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            let expected = a == 0;
            let is_eq: bool = evaluate!(&circ, a).unwrap();
            assert_eq!(is_eq, expected);
        }
    }

    #[test]
    fn test_all() {
        let mut builder: CircuitBuilder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());

        let is_all = all(&mut builder, &a);
        builder.add_output(is_all);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            let expected = if a != 255 { false } else { true };
            let is_eq: bool = evaluate!(&circ, a).unwrap();
            assert_eq!(is_eq, expected);
        }
    }

    #[test]
    fn test_lt() {
        let mut builder: CircuitBuilder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());
        let b: [_; 8] = from_fn(|_| builder.add_input());

        let is_lt = lt(&mut builder, a, b);
        builder.add_output(is_lt);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected = a < b;
                let is_lt: bool = evaluate!(&circ, a, b).unwrap();
                assert_eq!(is_lt, expected);
            }
        }
    }

    #[test]
    fn test_lte() {
        let mut builder: CircuitBuilder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());
        let b: [_; 8] = from_fn(|_| builder.add_input());

        let is_lt = lte(&mut builder, a, b);
        builder.add_output(is_lt);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected = a <= b;
                let is_lt: bool = evaluate!(&circ, a, b).unwrap();
                assert_eq!(is_lt, expected);
            }
        }
    }

    #[test]
    fn test_gt() {
        let mut builder: CircuitBuilder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());
        let b: [_; 8] = from_fn(|_| builder.add_input());

        let is_lt = gt(&mut builder, a, b);
        builder.add_output(is_lt);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected = a > b;
                let is_lt: bool = evaluate!(&circ, a, b).unwrap();
                assert_eq!(is_lt, expected);
            }
        }
    }

    #[test]
    fn test_gte() {
        let mut builder: CircuitBuilder = CircuitBuilder::new();

        let a: [_; 8] = from_fn(|_| builder.add_input());
        let b: [_; 8] = from_fn(|_| builder.add_input());

        let is_lt = gte(&mut builder, a, b);
        builder.add_output(is_lt);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected = a >= b;
                let is_lt: bool = evaluate!(&circ, a, b).unwrap();
                assert_eq!(is_lt, expected);
            }
        }
    }

    #[test]
    fn test_mul_by_10() {
        for i in 1u32..255021 {
            let mut builder = CircuitBuilder::new();

            let count = 32 - i.leading_zeros() as usize;
            let bits: Vec<_> = (0..count).map(|_| builder.add_input()).collect();
            let out = mul_by_10(&mut builder, &bits);
            for f in out {
                builder.add_output(f);
            }
            let circ = builder.build().unwrap();

            let bits = i.into_iter_lsb0().collect::<Vec<_>>();
            let output: Vec<bool> = evaluate!(circ, bits[0..count as usize]).unwrap();
            let out: u32 = <u32>::from_lsb0_iter(output.into_iter_lsb0());

            assert_eq!(out, i * 10);
        }
    }
}
