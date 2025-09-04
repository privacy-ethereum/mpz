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

/// Bitwise right rotation of an nbit value.
pub fn rotate_right_lsb<const N: usize>(a: [Node<Feed>; N], amount: usize) -> [Node<Feed>; N] {
    // Reverse the direction because bits are processed in lowest significant bit fashion.
    rotate(a, amount, Direction::Left)
}

/// Bitwise left rotation of an nbit value.
pub fn rotate_left_lsb<const N: usize>(a: [Node<Feed>; N], amount: usize) -> [Node<Feed>; N] {
    // Reverse the direction because bits are processed in lowest significant bit fashion.
    rotate(a, amount, Direction::Right)
}

enum Direction {
    Left,
    Right,
}

fn rotate<const N: usize>(a: [Node<Feed>; N], amount: usize, direction: Direction) -> [Node<Feed>; N] {
    if N == 0 || amount == 0 || amount % N == 0 {
        return a;
    }

    let amount = amount % N;

    match direction {
        Direction::Left => {
            std::array::from_fn(|i| a[(i + amount) % N])
        },
        Direction::Right => {
            std::array::from_fn(|i| a[(i + N - amount) % N])
        },
    }
}

/// Mixer used in Blake3 hashing.
/// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L41-L51.
pub fn blake3_mix(
    builder: &mut CircuitBuilder,
    a: [Node<Feed>; 32],
    b: [Node<Feed>; 32],
    c: [Node<Feed>; 32],
    d: [Node<Feed>; 32],
    mx: [Node<Feed>; 32],
    my: [Node<Feed>; 32],
) -> [[Node<Feed>; 32]; 4] {

    let a_1 = wrapping_add(builder, &a, &b);
    let a_2= wrapping_add(builder, &a_1, &mx);
    let d_1 = xor(builder, d, node_slice_to_array(&a_2));
    let d_2 = rotate_right_lsb(d_1, 16);
    let c_1 = wrapping_add(builder, &c, &d_2);
    let b_1 = xor(builder, b, node_slice_to_array(&c_1));
    let b_2 = rotate_right_lsb(b_1, 12);
    let a_3 = wrapping_add(builder, &a_2, &b_2);
    let a_4 = wrapping_add(builder, &a_3, &my);
    let d_3 = xor(builder, d_2, node_slice_to_array(&a_4));
    let d_4 = rotate_right_lsb(d_3, 8);
    let c_2 = wrapping_add(builder, &c_1, &d_4);
    let b_3 = xor(builder, b_2, node_slice_to_array(&c_2));
    let b_4 = rotate_right_lsb(b_3, 7);

    [node_slice_to_array(&a_4), b_4, node_slice_to_array(&c_2), d_4]
}

fn node_slice_to_array<const N: usize>(slice: &[Node<Feed>]) -> [Node<Feed>; N] 
{
    assert_eq!(slice.len(), N);
    slice.try_into().unwrap()
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

    #[test]
    fn test_rotate_right_lsb() {
        // Test 8-bit rotation
        let input: [Node<Feed>; 8] = std::array::from_fn(|i| Node::new(i));
        
        // Test rotation by 0 (should be identity)
        let result = rotate_right_lsb(input, 0);
        assert_eq!(result, input);
        
        // Test rotation by 1
        let result = rotate_right_lsb(input, 1);
        assert_eq!(result, [Node::new(1), Node::new(2), Node::new(3), Node::new(4), 
                           Node::new(5), Node::new(6), Node::new(7), Node::new(0)]);
        
        // Test rotation by 3
        let result = rotate_right_lsb(input, 3);
        assert_eq!(result, [Node::new(3), Node::new(4), Node::new(5), Node::new(6), 
                           Node::new(7), Node::new(0), Node::new(1), Node::new(2)]);
        
        // Test rotation by 8 (full rotation, should be identity)
        let result = rotate_right_lsb(input, 8);
        assert_eq!(result, input);
        
        // Test rotation by 9 (should be same as rotation by 1)
        let result = rotate_right_lsb(input, 9);
        assert_eq!(result, [Node::new(1), Node::new(2), Node::new(3), Node::new(4), 
                           Node::new(5), Node::new(6), Node::new(7), Node::new(0)]);
        
        // Test rotation by 16 (double full rotation, should be identity)
        let result = rotate_right_lsb(input, 16);
        assert_eq!(result, input);
    }

    #[test]
    fn test_rotate_left_lsb() {
        // Test 8-bit rotation
        let input: [Node<Feed>; 8] = std::array::from_fn(|i| Node::new(i));
        
        // Test rotation by 0 (should be identity)
        let result = rotate_left_lsb(input, 0);
        assert_eq!(result, input);
        
        // Test rotation by 1
        let result = rotate_left_lsb(input, 1);
        assert_eq!(result, [Node::new(7), Node::new(0), Node::new(1), Node::new(2), 
                           Node::new(3), Node::new(4), Node::new(5), Node::new(6)]);
        
        // Test rotation by 3
        let result = rotate_left_lsb(input, 3);
        assert_eq!(result, [Node::new(5), Node::new(6), Node::new(7), Node::new(0), 
                           Node::new(1), Node::new(2), Node::new(3), Node::new(4)]);
        
        // Test rotation by 8 (full rotation, should be identity)
        let result = rotate_left_lsb(input, 8);
        assert_eq!(result, input);
        
        // Test rotation by 9 (should be same as rotation by 1)
        let result = rotate_left_lsb(input, 9);
        assert_eq!(result, [Node::new(7), Node::new(0), Node::new(1), Node::new(2), 
                           Node::new(3), Node::new(4), Node::new(5), Node::new(6)]);
        
        // Test rotation by 16 (double full rotation, should be identity)
        let result = rotate_left_lsb(input, 16);
        assert_eq!(result, input);
    }

    #[test]
    fn test_rotate_edge_cases() {
        // Test empty array
        let empty: [Node<Feed>; 0] = [];
        let result = rotate_left_lsb(empty, 5);
        assert_eq!(result, empty);
        let result = rotate_right_lsb(empty, 5);
        assert_eq!(result, empty);
        
        // Test single element array
        let single: [Node<Feed>; 1] = [Node::new(42)];
        let result = rotate_left_lsb(single, 0);
        assert_eq!(result, single);
        let result = rotate_left_lsb(single, 1);
        assert_eq!(result, single);
        let result = rotate_left_lsb(single, 100);
        assert_eq!(result, single);
        let result = rotate_right_lsb(single, 0);
        assert_eq!(result, single);
        let result = rotate_right_lsb(single, 1);
        assert_eq!(result, single);
        let result = rotate_right_lsb(single, 100);
        assert_eq!(result, single);
        
        // Test two element array
        let two: [Node<Feed>; 2] = [Node::new(1), Node::new(2)];
        let result = rotate_left_lsb(two, 1);
        assert_eq!(result, [Node::new(2), Node::new(1)]);
        let result = rotate_left_lsb(two, 2);
        assert_eq!(result, two);
        let result = rotate_right_lsb(two, 1);
        assert_eq!(result, [Node::new(2), Node::new(1)]);
        let result = rotate_right_lsb(two, 2);
        assert_eq!(result, two);
    }


    #[test]
    fn test_blake3_mix() {
        // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L41-L51.
        fn expected_mix(state: &mut [u32; 4], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
            state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
            state[d] = (state[d] ^ state[a]).rotate_right(16);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] = (state[b] ^ state[c]).rotate_right(12);
            state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
            state[d] = (state[d] ^ state[a]).rotate_right(8);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] = (state[b] ^ state[c]).rotate_right(7);
        }

        let mut builder = CircuitBuilder::new();

        // Create inputs for the 4 state values and 2 mix values
        let a: [_; 32] = from_fn(|_| builder.add_input());
        let b: [_; 32] = from_fn(|_| builder.add_input());
        let c: [_; 32] = from_fn(|_| builder.add_input());
        let d: [_; 32] = from_fn(|_| builder.add_input());
        let mx: [_; 32] = from_fn(|_| builder.add_input());
        let my: [_; 32] = from_fn(|_| builder.add_input());

        let [out_a, out_b, out_c, out_d] = blake3_mix(&mut builder, a, b, c, d, mx, my);

        // Add outputs
        for node in out_a {
            builder.add_output(node);
        }
        for node in out_b {
            builder.add_output(node);
        }
        for node in out_c {
            builder.add_output(node);
        }
        for node in out_d {
            builder.add_output(node);
        }

        let circ = builder.build().unwrap();

        // Test case 1: All ones
        let mut state = [1u32; 4];
        expected_mix(&mut state, 0, 1, 2, 3, 1u32, 1u32);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, 1u32, 1u32, 1u32, 1u32, 1u32, 1u32).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);

        // Test case 2: All zeros (edge case)
        let mut state = [0u32; 4];
        expected_mix(&mut state, 0, 1, 2, 3, 0u32, 0u32);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);

        // Test case 3: Max values (overflow testing)
        let mut state = [u32::MAX; 4];
        expected_mix(&mut state, 0, 1, 2, 3, u32::MAX, u32::MAX);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);

        // Test case 4: Sequential values
        let mut state = [1u32, 2u32, 3u32, 4u32];
        expected_mix(&mut state, 0, 1, 2, 3, 5u32, 6u32);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, 1u32, 2u32, 3u32, 4u32, 5u32, 6u32).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);

        // Test case 5: Powers of two
        let mut state = [1u32, 2u32, 4u32, 8u32];
        expected_mix(&mut state, 0, 1, 2, 3, 16u32, 32u32);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, 1u32, 2u32, 4u32, 8u32, 16u32, 32u32).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);

        // Test case 6: Mix of zero and non-zero values
        let mut state = [0u32, u32::MAX, 0u32, u32::MAX];
        expected_mix(&mut state, 0, 1, 2, 3, 0x12345678u32, 0x9abcdef0u32);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, 0u32, u32::MAX, 0u32, u32::MAX, 0x12345678u32, 0x9abcdef0u32).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);

        // Test case 7: Large random-like values
        let mut state = [0xdeadbeefu32, 0xcafebabeu32, 0xfeedfaceu32, 0xbadc0dedu32];
        expected_mix(&mut state, 0, 1, 2, 3, 0x11111111u32, 0x22222222u32);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, 0xdeadbeefu32, 0xcafebabeu32, 0xfeedfaceu32, 0xbadc0dedu32, 0x11111111u32, 0x22222222u32).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);

        // Test case 8: Values with alternating bit patterns
        let mut state = [0xAAAAAAAAu32, 0x55555555u32, 0xFFFF0000u32, 0x0000FFFFu32];
        expected_mix(&mut state, 0, 1, 2, 3, 0xF0F0F0F0u32, 0x0F0F0F0Fu32);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, 0xAAAAAAAAu32, 0x55555555u32, 0xFFFF0000u32, 0x0000FFFFu32, 0xF0F0F0F0u32, 0x0F0F0F0Fu32).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);

        // Test case 9: Single bit set values
        let mut state = [1u32 << 31, 1u32 << 15, 1u32 << 7, 1u32 << 0];
        expected_mix(&mut state, 0, 1, 2, 3, 1u32 << 16, 1u32 << 8);
        
        let (out_a, out_b, out_c, out_d): (u32, u32, u32, u32) = 
            evaluate!(&circ, 1u32 << 31, 1u32 << 15, 1u32 << 7, 1u32 << 0, 1u32 << 16, 1u32 << 8).unwrap();
        
        assert_eq!(out_a, state[0]);
        assert_eq!(out_b, state[1]);
        assert_eq!(out_c, state[2]);
        assert_eq!(out_d, state[3]);
    }
}