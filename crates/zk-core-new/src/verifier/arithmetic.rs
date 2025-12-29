use mpz_memory_core::correlated::{Delta, Key, Mac};

use crate::{I32Key, Triple};

pub(crate) trait Cost {
    /// Number of masks required for the instruction.
    const MASKS: usize;
}

pub(crate) trait InstrArity1: Cost {
    type Arg;
    type Output;

    /// Execute the instruction.
    ///
    /// # Arguments
    /// - `v`: The input argument
    /// - `delta`: The global correlation value
    /// - `mask_bits`: Slice of adjustment bits from the prover
    /// - `masks`: Mutable slice of mask Keys
    /// - `triples`: Mutable slice to record AND triples
    fn execute(
        v: &Self::Arg,
        delta: &Delta,
        mask_bits: &[bool],
        masks: &mut [Key],
        triples: &mut [Triple<Key>],
    ) -> Self::Output;
}

pub(crate) trait InstrArity2: Cost {
    type Arg1;
    type Arg2;
    type Output;

    /// Execute the instruction.
    ///
    /// # Arguments
    /// - `a`: First input argument
    /// - `b`: Second input argument
    /// - `delta`: The global correlation value
    /// - `mask_bits`: Slice of adjustment bits from the prover
    /// - `masks`: Mutable slice of mask Keys
    /// - `triples`: Mutable slice to record AND triples
    fn execute(
        a: &Self::Arg1,
        b: &Self::Arg2,
        delta: &Delta,
        mask_bits: &[bool],
        masks: &mut [Key],
        triples: &mut [Triple<Key>],
    ) -> Self::Output;
}

/// Returns `true` if the provided bits are all true, otherwise `false`.
fn all(
    v: &[Key],
    delta: &Delta,
    mask_bits: &[bool],
    masks: &mut [Key],
    triples: &mut [Triple<Key>],
) -> Key {
    let len = v.len();
    debug_assert_eq!(mask_bits.len(), len);
    debug_assert_eq!(masks.len(), len);
    debug_assert_eq!(triples.len(), len);

    let mut i = 0;
    loop {
        let (a, b) = (&v[i], &v[i + 1]);

        let and = &mut masks[i];
        and.adjust(mask_bits[i], delta);
        triples[i] = Triple([*a, *b, *and]);

        i += 1;

        if i >= len - 1 {
            return *and;
        }
    }
}

pub(crate) struct I32Eqz;

impl Cost for I32Eqz {
    const MASKS: usize = 31;
}

impl InstrArity1 for I32Eqz {
    type Arg = I32Key;
    type Output = I32Key;

    #[inline]
    fn execute(
        v: &Self::Arg,
        delta: &Delta,
        mask_bits: &[bool],
        masks: &mut [Key],
        triples: &mut [Triple<Key>],
    ) -> Self::Output {
        let not = v.not(delta);
        I32Key::from_bool(all(&not.0, delta, mask_bits, masks, triples), delta)
    }
}

/// N-bit ripple-carry adder for verifier.
pub(crate) fn wrapping_add(
    a: &[Key],
    b: &[Key],
    result: &mut [Key],
    delta: &Delta,
    mask_bits: &[bool],
    masks: &mut [Key],
    triples: &mut [Triple<Key>],
) {
    let len = a.len();
    debug_assert_eq!(b.len(), len);
    debug_assert_eq!(result.len(), len);
    debug_assert_eq!(mask_bits.len(), len - 1);
    debug_assert_eq!(masks.len(), len - 1);
    debug_assert_eq!(triples.len(), len - 1);

    // Compute SUMs (Key + Key = XOR)
    result
        .iter_mut()
        .zip(a.iter().zip(b))
        .for_each(|(out, (a, b))| *out = *a + *b);

    // Step 2: Propagate carries
    // Bit 0: carry = a AND b (half adder)
    {
        let c = &mut masks[0];
        c.adjust(mask_bits[0], delta);
        triples[0] = Triple([a[0], b[0], *c]);
    }

    // Bits 1..N-1: c_out = c_in XOR ((a XOR c_in) AND (b XOR c_in))
    for i in 1..len - 1 {
        let c_in = masks[i - 1];

        // XOR carry into sum
        result[i] = result[i] + c_in;

        // Compute next carry: c_out = c_in XOR ((a XOR c_in) AND (b XOR c_in))
        let a_xor_c = a[i] + c_in;
        let b_xor_c = b[i] + c_in;

        let and_key = &mut masks[i];
        and_key.adjust(mask_bits[i], delta);
        triples[i] = Triple([a_xor_c, b_xor_c, *and_key]);

        // c_out = and XOR c_in
        masks[i] = *and_key + c_in;
    }

    // Last bit: just XOR in the final carry (no carry out needed)
    if len > 1 {
        let c_in = masks[len - 2];
        result[len - 1] = result[len - 1] + c_in;
    }
}

pub(crate) struct I32Add;

impl Cost for I32Add {
    // Ripple-carry adder using the optimized full-adder formula:
    // C_OUT = C_IN ⊕ ((A ⊕ C_IN) ∧ (B ⊕ C_IN))
    // This uses only 1 AND per carry bit.
    // - Bit 0: half_adder (1 AND for carry)
    // - Bits 1..30: full_adder (1 AND each for carry)
    // - Bit 31: no carry needed
    // Total: 31 ANDs
    const MASKS: usize = 31;
}

impl InstrArity2 for I32Add {
    type Arg1 = I32Key;
    type Arg2 = I32Key;
    type Output = I32Key;

    #[inline]
    fn execute(
        a: &Self::Arg1,
        b: &Self::Arg2,
        delta: &Delta,
        mask_bits: &[bool],
        masks: &mut [Key],
        triples: &mut [Triple<Key>],
    ) -> Self::Output {
        let mut result = I32Key::default();
        wrapping_add(&a.0, &b.0, &mut result.0, delta, mask_bits, masks, triples);
        result
    }
}
