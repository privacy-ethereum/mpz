use mpz_memory_core::correlated::Mac;

use crate::{I32Mac, Triple};

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
    /// - `mask_bits`: Mutable slice for adjustment bits (will be XORed with
    ///   actual AND results)
    /// - `masks`: Mutable slice of mask MACs
    /// - `triples`: Mutable slice to record AND triples
    fn execute(
        v: &Self::Arg,
        mask_bits: &mut [bool],
        masks: &mut [Mac],
        triples: &mut [Triple<Mac>],
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
    /// - `mask_bits`: Mutable slice for adjustment bits (will be XORed with
    ///   actual AND results)
    /// - `masks`: Mutable slice of mask MACs
    /// - `triples`: Mutable slice to record AND triples
    fn execute(
        a: &Self::Arg1,
        b: &Self::Arg2,
        mask_bits: &mut [bool],
        masks: &mut [Mac],
        triples: &mut [Triple<Mac>],
    ) -> Self::Output;
}

/// Returns `true` if the provided bits are all true, otherwise `false`.
pub(crate) fn all(
    v: &[Mac],
    mask_bits: &mut [bool],
    masks: &mut [Mac],
    triples: &mut [Triple<Mac>],
) -> Mac {
    let len = v.len();
    debug_assert_eq!(mask_bits.len(), len);
    debug_assert_eq!(masks.len(), len);
    debug_assert_eq!(triples.len(), len);

    let mut i = 0;
    loop {
        let (a, b) = (&v[i], &v[i + 1]);

        let and = &mut masks[i];
        let and_bit = a.pointer() & b.pointer();
        and.set_pointer(and_bit);
        mask_bits[i] ^= and_bit;
        triples[i] = Triple([*a, *b, *and]);

        i += 1;

        if i >= len - 1 {
            return *and;
        }
    }
}

/// N-bit ripple-carry adder.
pub(crate) fn wrapping_add(
    a: &[Mac],
    b: &[Mac],
    result: &mut [Mac],
    mask_bits: &mut [bool],
    masks: &mut [Mac],
    triples: &mut [Triple<Mac>],
) {
    let len = a.len();
    debug_assert_eq!(b.len(), len);
    debug_assert_eq!(result.len(), len);
    debug_assert_eq!(mask_bits.len(), len - 1);
    debug_assert_eq!(masks.len(), len - 1);
    debug_assert_eq!(triples.len(), len - 1);

    // Compute SUMs
    result
        .iter_mut()
        .zip(a.iter().zip(b))
        .for_each(|(out, (a, b))| *out = a ^ b);

    // Step 2: Propagate carries
    // Bit 0: carry = a AND b (half adder)
    {
        let c_bit = a[0].pointer() & b[0].pointer();
        let c = &mut masks[0];
        c.set_pointer(c_bit);
        mask_bits[0] ^= c_bit;
        triples[0] = Triple([a[0], b[0], *c]);
    }

    // Bits 1..N-1: c_out = c_in XOR ((a XOR c_in) AND (b XOR c_in))
    for i in 1..len - 1 {
        let c_in = masks[i - 1];

        // XOR carry into sum
        result[i] = result[i] ^ c_in;

        // Compute next carry: c_out = c_in XOR ((a XOR c_in) AND (b XOR c_in))
        let a_xor_c = a[i] ^ c_in;
        let b_xor_c = b[i] ^ c_in;

        let and_bit = a_xor_c.pointer() & b_xor_c.pointer();
        let and_mac = &mut masks[i];
        and_mac.set_pointer(and_bit);
        mask_bits[i] ^= and_bit;
        triples[i] = Triple([a_xor_c, b_xor_c, *and_mac]);

        // c_out = and XOR c_in
        masks[i] = *and_mac ^ c_in;
    }

    // Last bit: just XOR in the final carry (no carry out needed)
    if len > 1 {
        let c_in = masks[len - 2];
        result[len - 1] = result[len - 1] ^ c_in;
    }
}

pub(crate) struct I32Eqz;

impl Cost for I32Eqz {
    const MASKS: usize = 31;
}

impl InstrArity1 for I32Eqz {
    type Arg = I32Mac;
    type Output = I32Mac;

    #[inline]
    fn execute(
        v: &Self::Arg,
        mask_bits: &mut [bool],
        masks: &mut [Mac],
        triples: &mut [Triple<Mac>],
    ) -> Self::Output {
        let not = !v;
        I32Mac::from_bool(all(&not.0, mask_bits, masks, triples))
    }
}

pub(crate) struct I32Add;

impl Cost for I32Add {
    const MASKS: usize = 31;
}

impl InstrArity2 for I32Add {
    type Arg1 = I32Mac;
    type Arg2 = I32Mac;
    type Output = I32Mac;

    #[inline]
    fn execute(
        a: &Self::Arg1,
        b: &Self::Arg2,
        mask_bits: &mut [bool],
        masks: &mut [Mac],
        triples: &mut [Triple<Mac>],
    ) -> Self::Output {
        let mut result = I32Mac::default();
        wrapping_add(&a.0, &b.0, &mut result.0, mask_bits, masks, triples);
        result
    }
}
