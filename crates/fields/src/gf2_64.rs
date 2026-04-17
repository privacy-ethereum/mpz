//! This module implements the extension field GF(2^64).
//!
//! Uses the irreducible polynomial p(x) = x^64 + x^4 + x^3 + x + 1.

use std::ops::{Add, Mul, Neg, Sub};

use hybrid_array::{
    Array,
    typenum::{U8, U64},
};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::distr::{Distribution, StandardUniform};
use serde::{Deserialize, Serialize};

use crate::{Field, FieldError};

/// An element of GF(2^64), represented as a `u64`.
///
/// Field arithmetic uses the irreducible polynomial
/// p(x) = x^64 + x^4 + x^3 + x + 1.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Gf2_64(pub u64);

impl Gf2_64 {
    /// The additive identity (zero).
    pub const ZERO: Self = Gf2_64(0);
    /// The multiplicative identity (one).
    pub const ONE: Self = Gf2_64(1);
}

impl Add for Gf2_64 {
    type Output = Self;
    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        Gf2_64(self.0 ^ rhs.0)
    }
}

impl Sub for Gf2_64 {
    type Output = Self;
    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        // Characteristic-2: subtraction equals addition.
        Gf2_64(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2_64 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Gf2_64(gf64_mul(self.0, rhs.0))
    }
}

impl Neg for Gf2_64 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        // Characteristic-2: -x = x.
        self
    }
}

impl Distribution<Gf2_64> for StandardUniform {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Gf2_64 {
        Gf2_64(self.sample(rng))
    }
}

impl TryFrom<Array<u8, U8>> for Gf2_64 {
    type Error = FieldError;

    fn try_from(value: Array<u8, U8>) -> Result<Self, Self::Error> {
        let inner: [u8; 8] = value.into();
        Ok(Gf2_64(u64::from_be_bytes(inner)))
    }
}

impl BitLength for Gf2_64 {
    const BITS: usize = 64;
}

impl GetBit<Lsb0> for Gf2_64 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Lsb0>::get_bit(&self.0, index)
    }
}

impl GetBit<Msb0> for Gf2_64 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Msb0>::get_bit(&self.0, index)
    }
}

impl FromBitIterator for Gf2_64 {
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Gf2_64(u64::from_lsb0_iter(iter))
    }

    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Gf2_64(u64::from_msb0_iter(iter))
    }
}

impl Field for Gf2_64 {
    type BitSize = U64;
    type ByteSize = U8;

    fn zero() -> Self {
        Gf2_64::ZERO
    }

    fn one() -> Self {
        Gf2_64::ONE
    }

    fn two_pow(rhs: u32) -> Self {
        Gf2_64(1u64 << rhs)
    }

    fn inverse(self) -> Option<Self> {
        if self == Gf2_64::ZERO {
            return None;
        }
        // Fermat in GF(2⁶⁴): x⁻¹ = x^(2⁶⁴ − 2) = x² · x⁴ · … · x^(2⁶³).
        let mut y = self * self; // x²
        let mut result = y;
        for _ in 2..64 {
            y = y * y;
            result = result * y;
        }
        Some(result)
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

/// Carry-less multiply + reduce in XMM registers (SSE2 + PCLMULQDQ).
#[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
#[inline(always)]
#[allow(unsafe_code)]
fn gf64_mul(a: u64, b: u64) -> u64 {
    use std::arch::x86_64::*;

    unsafe {
        let a_vec = _mm_set_epi64x(0, a as i64);
        let b_vec = _mm_set_epi64x(0, b as i64);
        let prod = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);

        // hi = bits 64..127 of the product (byte-shift right by 8).
        let hi = _mm_srli_si128(prod, 8);

        // Round 1: lo ^= hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4)
        let h1 = _mm_slli_epi64(hi, 1);
        let h3 = _mm_slli_epi64(hi, 3);
        let h4 = _mm_slli_epi64(hi, 4);
        let folded = _mm_xor_si128(
            _mm_xor_si128(prod, hi),
            _mm_xor_si128(_mm_xor_si128(h1, h3), h4),
        );

        // Round 2: overflow from hi<<1/3/4 lands in bits 64..67.
        let hi2 = _mm_xor_si128(
            _mm_srli_epi64(hi, 63),
            _mm_xor_si128(_mm_srli_epi64(hi, 61), _mm_srli_epi64(hi, 60)),
        );
        let h2_1 = _mm_slli_epi64(hi2, 1);
        let h2_3 = _mm_slli_epi64(hi2, 3);
        let h2_4 = _mm_slli_epi64(hi2, 4);
        let result = _mm_xor_si128(
            _mm_xor_si128(folded, hi2),
            _mm_xor_si128(_mm_xor_si128(h2_1, h2_3), h2_4),
        );

        _mm_cvtsi128_si64(result) as u64
    }
}

/// Portable carry-less multiply + reduce fallback.
#[cfg(not(all(target_arch = "x86_64", target_feature = "pclmulqdq")))]
#[inline]
fn gf64_mul(a: u64, b: u64) -> u64 {
    // R = x⁴ + x³ + x + 1 = 0b11011 = 0x1b.
    const R: u64 = 0x1b;

    let mut x = a;
    let mut y = b;
    let mut z = 0u64;

    while (x != 0) && (y != 0) {
        z ^= (y & 1) * x;
        x = (x << 1) ^ ((x >> 63) * R);
        y >>= 1;
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let zero = Gf2_64::ZERO;
        let one = Gf2_64::ONE;

        assert_eq!(one * one, one);
        assert_eq!(one * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one + one, zero);
        assert_eq!(one + zero, one);
    }

    #[test]
    fn test_associativity() {
        let a = Gf2_64(0x123456789ABCDEF0);
        let b = Gf2_64(0xFEDCBA9876543210);
        let c = Gf2_64(0xDEADBEEFCAFEBABE);

        let ab_c = (a * b) * c;
        let a_bc = a * (b * c);
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn test_commutativity() {
        let a = Gf2_64(0xAAAABBBBCCCCDDDD);
        let b = Gf2_64(0x1111222233334444);

        assert_eq!(a * b, b * a);
    }

    #[test]
    fn test_distributivity() {
        let a = Gf2_64(0x123456789ABCDEF0);
        let b = Gf2_64(0xFEDCBA9876543210);
        let c = Gf2_64(0xDEADBEEFCAFEBABE);

        // a * (b + c) = a*b + a*c
        let lhs = a * (b + c);
        let rhs = a * b + a * c;
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_inv_round_trip() {
        // For a handful of nonzero elements, x · inv(x) = 1.
        for raw in [
            1u64,
            2,
            3,
            0x1234_5678,
            0xDEAD_BEEF_CAFE_BABE,
            0xFFFF_FFFF_FFFF_FFFF,
        ] {
            let x = Gf2_64(raw);
            let xi = x.inverse().unwrap();
            assert_eq!(x * xi, Gf2_64::ONE, "x={raw:#x}");
        }
    }

    /// Reference GF(2⁶⁴) multiplication.
    fn reference_mul(a: u64, b: u64) -> u64 {
        use crate::test_data::{GF64_TO_SWANKY, SWANKY_TO_GF64};
        use swanky_field_binary::F64b;
        use swanky_serialization::CanonicalSerialize;

        fn mat_mul(rows: &[u64; 64], x: u64) -> u64 {
            let mut result = 0u64;
            for (i, row) in rows.iter().enumerate() {
                let dot = (row & x).count_ones() & 1;
                result |= (dot as u64) << i;
            }
            result
        }

        // Convert to Swanky basis, multiply, convert back.
        let a_s = mat_mul(&GF64_TO_SWANKY, a);
        let b_s = mat_mul(&GF64_TO_SWANKY, b);
        let c_s = F64b::from(a_s) * F64b::from(b_s);
        let bytes = c_s.to_bytes();
        let c_s_u64 = u64::from_le_bytes(bytes.as_slice().try_into().unwrap());
        mat_mul(&SWANKY_TO_GF64, c_s_u64)
    }

    #[test]
    fn test_mul_against_reference() {
        use mpz_core::{Block, prg::Prg};
        use rand::{Rng, SeedableRng};

        fn check(a: u64, b: u64) {
            let ours = (Gf2_64(a) * Gf2_64(b)).0;
            let ref_val = reference_mul(a, b);
            assert_eq!(
                ours, ref_val,
                "mismatch: a={a:#018x} b={b:#018x} ours={ours:#018x} ref={ref_val:#018x}"
            );
        }

        // Edge cases: identity, zero, inverse.
        let x = 0xDEAD_BEEF_CAFE_BABE;
        check(x, 1); // a * 1 = a
        check(1, x); // 1 * a = a
        check(x, 0); // a * 0 = 0
        check(0, x); // 0 * a = 0

        // All bits set — maximum carry during reduction.
        check(u64::MAX, u64::MAX);

        // Single high bit — product has bit 126 set.
        check(1 << 63, 1 << 63);

        // Minimal reduction trigger — product has exactly bit 64 set.
        check(1 << 32, 1 << 32);

        // Bits near the reduction polynomial taps (x⁴, x³, x¹).
        check(1 << 4, 1 << 60);
        check(1 << 3, 1 << 61);

        // The reduction constant itself as a field element.
        check(0x1b, 0x1b);

        // Squaring — catches asymmetric bugs.
        check(0xAAAA_AAAA_AAAA_AAAA, 0xAAAA_AAAA_AAAA_AAAA);

        // Miri is ~100x slower, so shrink the random sweep under it.
        let iters = if cfg!(miri) { 100 } else { 1000 };
        let mut rng = Prg::from_seed(Block::ZERO);
        for _ in 0..iters {
            let a: u64 = rng.random();
            let b: u64 = rng.random();
            check(a, b);
        }
    }
}
