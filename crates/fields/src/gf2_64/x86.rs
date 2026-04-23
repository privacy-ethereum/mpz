//! x86_64 PCLMULQDQ fast path for GF(2⁶⁴). Multiply and inner-product
//! share the 128-bit reduction helper (`reduce64`).
#![allow(unsafe_code)]

use std::arch::x86_64::*;

use super::Gf2_64;

#[inline(always)]
pub(super) fn mul(a: u64, b: u64) -> u64 {
    // SAFETY: gated on `target_feature = "pclmulqdq"`, SSE2 + PCLMULQDQ
    // are guaranteed available.
    unsafe {
        let a_vec = _mm_set_epi64x(0, a as i64);
        let b_vec = _mm_set_epi64x(0, b as i64);
        let prod = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);
        _mm_cvtsi128_si64(reduce64(prod)) as u64
    }
}

/// Multiplicative inverse via Fermat's little theorem — keeps the running
/// state in XMM across all 63 squarings + 62 accumulating multiplies.
#[inline(always)]
pub(super) fn inverse(a: u64) -> u64 {
    // SAFETY: see `mul`.
    unsafe {
        let x = _mm_set_epi64x(0, a as i64);
        // Fermat: x⁻¹ = x^(2⁶⁴ − 2) = x² · x⁴ · … · x^(2⁶³).
        let mut y = mul_xmm(x, x); // x²
        let mut out = y;
        for _ in 2..64 {
            y = mul_xmm(y, y);
            out = mul_xmm(out, y);
        }
        _mm_cvtsi128_si64(out) as u64
    }
}

#[inline(always)]
unsafe fn mul_xmm(a: __m128i, b: __m128i) -> __m128i {
    unsafe {
        // CLMUL uses the low 64 of each operand (selector 0x00); the high 64
        // of `reduce64`'s output is garbage, which is fine because the next
        // call only reads the low 64.
        let prod = _mm_clmulepi64_si128(a, b, 0x00);
        reduce64(prod)
    }
}

#[inline(always)]
pub(super) fn inner_product(a: &[Gf2_64], b: &[Gf2_64]) -> u64 {
    // SAFETY: see `mul`.
    unsafe {
        let mut acc = _mm_setzero_si128();

        // Accumulate 128-bit carry-less products; reduce once at the end.
        for (x, y) in a.iter().zip(b.iter()) {
            let a_vec = _mm_set_epi64x(0, x.0 as i64);
            let b_vec = _mm_set_epi64x(0, y.0 as i64);
            let prod = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);
            acc = _mm_xor_si128(acc, prod);
        }

        _mm_cvtsi128_si64(reduce64(acc)) as u64
    }
}

/// Reduce a 128-bit polynomial (in the low/high halves of `prod`) modulo
/// p(x) = x⁶⁴ + x⁴ + x³ + x + 1.
#[inline(always)]
unsafe fn reduce64(prod: __m128i) -> __m128i {
    unsafe {
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
        _mm_xor_si128(
            _mm_xor_si128(folded, hi2),
            _mm_xor_si128(_mm_xor_si128(h2_1, h2_3), h2_4),
        )
    }
}
