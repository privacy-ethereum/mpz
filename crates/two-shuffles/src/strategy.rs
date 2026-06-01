//! Field-strategy traits.

use std::marker::PhantomData;

use itybity::{FromBitIterator, ToBits};
use mpz_fields::{Field, gf2::Gf2};
use mpz_poly_proof_core::ExtensionField;

pub mod version;

use version::{AdditiveStep, MultiplicativeStep, ProverVersionStep, VerifierVersionStep};

// ---------------------------------------------------------------------------
// Field-property markers
// ---------------------------------------------------------------------------
/// Marker: this field has characteristic 2 (`1 + 1 = 0`).
pub trait Char2 {}

impl Char2 for mpz_fields::gf2_64::Gf2_64 {}
impl Char2 for mpz_fields::gf2_128::Gf2_128 {}

/// Marker: in this field, the `+1` chain produces distinct values
/// and field `+`/`−` coincide with integer arithmetic over the
/// protocol's range `0..=T`.
pub trait IntegerLike {}

// ---------------------------------------------------------------------------
// Trait hierarchy
// ---------------------------------------------------------------------------

/// Base layer: subfield element type + wire-length sizing.
///
/// Every wire in any protocol is a [`Bundle<S>`](crate::Bundle); this
/// trait pins the `S` and provides the conversion from a user-facing
/// "number of distinct values" to the corresponding wire length.
pub trait FieldStrategy<F: Field> {
    /// Subfield element type used for cleartext slots.
    type S: Field;

    /// Compute the wire length needed to encode `n` distinct values.
    ///
    /// # Panics
    ///
    /// Panics if `n < 2` (encoding requires at least two distinct
    /// values), or if `n`'s required wire length exceeds `F`'s
    /// extension degree over [`Self::S`] (the bundle would not fit
    /// in a single `F` element).
    fn wire_length_for(n: usize) -> usize;

    /// Compute the wire length needed to encode a value domain of
    /// `value_bits` bits (i.e. `2^value_bits` distinct values).
    ///
    /// # Panics
    ///
    /// Panics if `value_bits == 0` (encoding requires at least two
    /// distinct values), or if the required wire length exceeds `F`'s
    /// capacity.
    fn wire_length_for_log2(value_bits: usize) -> usize;

    /// Convert a bundle to its integer index.
    ///
    /// The caller is responsible for passing a bundle that the
    /// encoding can map to a valid index. Inputs outside the
    /// encoding's representable range produce an unspecified `u32`;
    /// no representability check is performed.
    fn bundle_to_index(bundle: &[Self::S]) -> u32;

    /// Produce the cleartext bundle that encodes `idx`. `length` is
    /// the wire length (slot count) of the encoding.
    fn index_to_bundle(idx: u32, length: usize) -> Vec<Self::S>;
}

/// Per-key version-chain step strategy.
///
/// The protocols built on this trait attach a *version counter* to
/// every key and advance it by one step on every access. This trait
/// pins the rule for what "one step" means.
pub trait VersionStrategy<F: Field>: FieldStrategy<F>
where
    F: ExtensionField<Self::S>,
{
    /// The rule used to advance the per-key version counter on
    /// every access.
    type VersionStep: ProverVersionStep<Self::S, F> + VerifierVersionStep<Self::S, F>;
}

/// Strategy for char-2 extension fields with `Gf2` as the subfield
/// element.
pub struct Char2Strategy<F>(PhantomData<F>);

impl<F> FieldStrategy<F> for Char2Strategy<F>
where
    F: Field + Char2,
{
    type S = Gf2;

    fn wire_length_for(n: usize) -> usize {
        // Gf2-bundle encoding: ceil(log2(n)) Gf2 slots represent `n`
        // distinct values.
        assert!(
            n >= 2,
            "Char2Strategy: n={n} too small (need at least 2 distinct values)"
        );
        let bits = n.next_power_of_two().trailing_zeros() as usize;
        assert!(
            bits <= F::BIT_SIZE,
            "Char2Strategy: n={n} exceeds field capacity 2^{}",
            F::BIT_SIZE,
        );
        bits
    }

    fn wire_length_for_log2(value_bits: usize) -> usize {
        // Gf2-bundle encoding: one Gf2 slot per bit.
        assert!(
            value_bits >= 1,
            "Char2Strategy: value_bits must be ≥ 1 (need at least 2 distinct values)"
        );
        assert!(
            value_bits <= F::BIT_SIZE,
            "Char2Strategy: value_bits={value_bits} exceeds field capacity 2^{}",
            F::BIT_SIZE,
        );
        value_bits
    }

    // LSB-first bit pack: bit `i` of the bundle becomes bit `i` of
    // the returned `u32`.
    #[inline]
    fn bundle_to_index(bundle: &[Gf2]) -> u32 {
        debug_assert!(bundle.len() <= 32, "wire length exceeds u32");
        u32::from_lsb0_iter(bundle.iter_lsb0())
    }

    /// LSB-first bit decomposition: bit `i` of `idx` becomes slot `i`
    /// of the returned bundle.
    #[inline]
    fn index_to_bundle(idx: u32, length: usize) -> Vec<Gf2> {
        debug_assert!(length <= 32, "wire length exceeds u32");
        Vec::<Gf2>::from_lsb0_iter(idx.iter_lsb0().take(length))
    }
}

impl<F> VersionStrategy<F> for Char2Strategy<F>
where
    F: Field + Char2 + ExtensionField<Gf2>,
{
    type VersionStep = MultiplicativeStep;
}

/// Strategy for prime fields with single-wire value encoding.
pub struct PrimeFieldStrategy<F>(PhantomData<F>);

impl<F> FieldStrategy<F> for PrimeFieldStrategy<F>
where
    F: Field + IntegerLike,
{
    type S = F;

    fn wire_length_for(n: usize) -> usize {
        // Single-wire encoding: one field element holds any value
        // up to `|F|`. Wire length is always 1 if `n` fits.
        assert!(
            n >= 2,
            "PrimeFieldStrategy: n={n} too small (need at least 2 distinct values)"
        );
        // `n > 2^BIT_SIZE` exceeds the field. Skip the shift if the
        // bound is unreachable on `usize` (e.g. P256: BIT_SIZE = 256).
        if F::BIT_SIZE < usize::BITS as usize {
            assert!(
                n <= (1usize << F::BIT_SIZE),
                "PrimeFieldStrategy: n={n} exceeds field capacity 2^{}",
                F::BIT_SIZE,
            );
        }
        1
    }

    fn wire_length_for_log2(value_bits: usize) -> usize {
        // Single-wire encoding: one field element holds the value.
        assert!(
            value_bits >= 1,
            "PrimeFieldStrategy: value_bits must be ≥ 1 (need at least 2 distinct values)"
        );
        assert!(
            value_bits <= F::BIT_SIZE,
            "PrimeFieldStrategy: value_bits={value_bits} exceeds field capacity 2^{}",
            F::BIT_SIZE,
        );
        1
    }

    // Take the low 32 bits of the single field element's
    // little-endian byte representation.
    #[inline]
    fn bundle_to_index(bits: &[F]) -> u32 {
        debug_assert_eq!(bits.len(), 1, "PrimeFieldStrategy wire length is 1");
        let bytes = bits[0].to_le_bytes();
        let (head, _) = bytes.split_at(std::mem::size_of::<u32>());
        u32::from_le_bytes(head.try_into().expect("4 bytes or less"))
    }

    #[inline]
    fn index_to_bundle(idx: u32, length: usize) -> Vec<F> {
        debug_assert_eq!(length, 1, "PrimeFieldStrategy wire length is 1");
        let mut buf = hybrid_array::Array::<u8, F::ByteSize>::default();
        buf.as_mut_slice()[..4].copy_from_slice(&idx.to_le_bytes());
        let f = F::try_from(buf).expect("zero-padded u32 fits any prime field");
        vec![f]
    }
}

impl<F> VersionStrategy<F> for PrimeFieldStrategy<F>
where
    F: ExtensionField<F> + IntegerLike,
{
    type VersionStep = AdditiveStep;
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_fields::{gf2_64::Gf2_64, p256::P256};

    #[test]
    fn char2_wire_length_for_table() {
        // ceil(log2(n)) for n in {2..=16, plus a few boundaries above}.
        let cases = [
            (2usize, 1usize),
            (3, 2),
            (4, 2),
            (5, 3),
            (7, 3),
            (8, 3),
            (9, 4),
            (16, 4),
            (17, 5),
            (255, 8),
            (256, 8),
            (257, 9),
            (1024, 10),
            (1025, 11),
        ];
        for (n, expected) in cases {
            let got = Char2Strategy::<Gf2_64>::wire_length_for(n);
            assert_eq!(got, expected, "Char2 wire_length_for({n}) mismatch");
        }
    }

    #[test]
    #[should_panic(expected = "too small")]
    fn char2_wire_length_for_panics_on_n_zero() {
        let _ = Char2Strategy::<Gf2_64>::wire_length_for(0);
    }

    #[test]
    fn char2_wire_length_for_log2_is_identity() {
        for value_bits in 1..=Gf2_64::BIT_SIZE {
            assert_eq!(
                Char2Strategy::<Gf2_64>::wire_length_for_log2(value_bits),
                value_bits,
            );
        }
    }

    #[test]
    #[should_panic(expected = "value_bits must be ≥ 1")]
    fn char2_wire_length_for_log2_panics_on_zero() {
        let _ = Char2Strategy::<Gf2_64>::wire_length_for_log2(0);
    }

    #[test]
    #[should_panic(expected = "exceeds field capacity")]
    fn char2_wire_length_for_log2_panics_over_capacity() {
        let _ = Char2Strategy::<Gf2_64>::wire_length_for_log2(Gf2_64::BIT_SIZE + 1);
    }

    #[test]
    fn prime_wire_length_for_log2_is_always_one() {
        // P256 holds any value up to 256 bits in a single wire — a
        // domain the cardinality-based API cannot even express.
        for value_bits in [1usize, 8, 32, 64, 128, 256] {
            assert_eq!(
                PrimeFieldStrategy::<P256>::wire_length_for_log2(value_bits),
                1
            );
        }
    }

    #[test]
    #[should_panic(expected = "too small")]
    fn char2_wire_length_for_panics_on_n_one() {
        let _ = Char2Strategy::<Gf2_64>::wire_length_for(1);
    }

    #[test]
    fn prime_wire_length_for_is_always_one() {
        // Single-wire encoding: any `n >= 2` that fits in the field
        // produces wire length 1. P256 has BIT_SIZE = 256, so the
        // capacity assertion is unreachable on `usize`.
        for &n in &[2usize, 3, 100, 1024, usize::MAX] {
            let got = PrimeFieldStrategy::<P256>::wire_length_for(n);
            assert_eq!(got, 1, "PrimeField wire_length_for({n}) ≠ 1");
        }
    }

    #[test]
    #[should_panic(expected = "too small")]
    fn prime_wire_length_for_panics_on_n_zero() {
        let _ = PrimeFieldStrategy::<P256>::wire_length_for(0);
    }

    #[test]
    #[should_panic(expected = "too small")]
    fn prime_wire_length_for_panics_on_n_one() {
        let _ = PrimeFieldStrategy::<P256>::wire_length_for(1);
    }
}
