//! x86_64 PCLMULQDQ fast path for GF(2¹²⁸). Multiply and inner-product
//! share carry-less multiply (`clmul128`) and reduction (`reduce128`).
#![allow(unsafe_code)]

use std::arch::x86_64::*;

use super::Gf2_128;

#[inline(always)]
pub(super) fn mul(a: u128, b: u128) -> u128 {
    // SAFETY: gated on `target_feature = "pclmulqdq"`, SSE2 + PCLMULQDQ
    // are guaranteed available.
    unsafe {
        let a_vec = load(a);
        let b_vec = load(b);
        let (lo, hi) = clmul128(a_vec, b_vec);
        extract(reduce128(lo, hi))
    }
}

/// Squaring uses only two CLMULs instead of four. In characteristic 2,
/// `(a_lo + a_hi · x⁶⁴)² = a_lo² + a_hi² · x¹²⁸` — the cross term
/// `2·a_lo·a_hi` vanishes. So we only need `a_lo²` (for bits [0..128])
/// and `a_hi²` (for bits [128..256]); the two middle CLMULs that a
/// general `mul` needs drop out entirely.
#[inline(always)]
pub(super) fn square(a: u128) -> u128 {
    // SAFETY: see `mul`.
    unsafe {
        let a_vec = load(a);
        let (lo, hi) = sq128(a_vec);
        extract(reduce128(lo, hi))
    }
}

/// Multiplicative inverse via Fermat's little theorem — keeps the running
/// state in XMM across all 127 squarings + 126 accumulating multiplies,
/// collapsing 254 GPR↔XMM transfers down to 2. Uses the 2-CLMUL
/// squaring path on the squaring half of the chain.
#[inline(always)]
pub(super) fn inverse(a: u128) -> u128 {
    // SAFETY: see `mul`.
    unsafe {
        let x = load(a);
        // Fermat: x⁻¹ = x^(2¹²⁸ − 2) = x² · x⁴ · x⁸ · … · x^(2¹²⁷).
        let mut y = square_xmm(x); // x²
        let mut out = y;
        for _ in 2..128 {
            y = square_xmm(y); // y ← y² (2 CLMULs)
            out = mul_xmm(out, y); // out ← out · y (4 CLMULs)
        }
        extract(out)
    }
}

#[inline(always)]
unsafe fn mul_xmm(a: __m128i, b: __m128i) -> __m128i {
    unsafe {
        let (lo, hi) = clmul128(a, b);
        reduce128(lo, hi)
    }
}

#[inline(always)]
unsafe fn square_xmm(a: __m128i) -> __m128i {
    unsafe {
        let (lo, hi) = sq128(a);
        reduce128(lo, hi)
    }
}

#[inline(always)]
pub(super) fn inner_product(a: &[Gf2_128], b: &[Gf2_128]) -> u128 {
    // SAFETY: see `mul`.
    unsafe {
        let mut acc_lo = _mm_setzero_si128();
        let mut acc_hi = _mm_setzero_si128();

        // Accumulate 256-bit carry-less products; reduce once at the end.
        for (x, y) in a.iter().zip(b.iter()) {
            let (lo, hi) = clmul128(load(x.0), load(y.0));
            acc_lo = _mm_xor_si128(acc_lo, lo);
            acc_hi = _mm_xor_si128(acc_hi, hi);
        }

        extract(reduce128(acc_lo, acc_hi))
    }
}

/// 256-bit carry-less square of a 128-bit input (two 64×64 CLMULs). In
/// characteristic 2, all cross terms vanish — we only need `a_lo²`
/// (for bits [0..128]) and `a_hi²` (for bits [128..256]).
#[inline(always)]
unsafe fn sq128(a: __m128i) -> (__m128i, __m128i) {
    unsafe {
        let lo = _mm_clmulepi64_si128(a, a, 0x00); // a_lo · a_lo
        let hi = _mm_clmulepi64_si128(a, a, 0x11); // a_hi · a_hi
        (lo, hi)
    }
}

/// 256-bit carry-less product of two 128-bit inputs (four 64×64 CLMULs).
///
/// Returns `(lo, hi)` such that the 256-bit product is `hi·x^128 + lo`.
#[inline(always)]
unsafe fn clmul128(a: __m128i, b: __m128i) -> (__m128i, __m128i) {
    unsafe {
        //   t00 = a_lo · b_lo  → bits [0..128]
        //   t11 = a_hi · b_hi  → bits [128..256]
        //   t01 = a_hi · b_lo  → bits  [64..192]
        //   t10 = a_lo · b_hi  → bits  [64..192]
        let t00 = _mm_clmulepi64_si128(a, b, 0x00);
        let t11 = _mm_clmulepi64_si128(a, b, 0x11);
        let t01 = _mm_clmulepi64_si128(a, b, 0x01);
        let t10 = _mm_clmulepi64_si128(a, b, 0x10);

        let mid = _mm_xor_si128(t01, t10);
        let lo = _mm_xor_si128(t00, _mm_slli_si128(mid, 8));
        let hi = _mm_xor_si128(t11, _mm_srli_si128(mid, 8));
        (lo, hi)
    }
}

/// Reduce a 256-bit polynomial `hi·x^128 + lo` modulo p(x) = x^128 + x^7 +
/// x^2 + x + 1. Since x^128 ≡ R = x^7 + x^2 + x + 1 (mod p), the result
/// is `lo + hi · R (mod p)`, computed in two CLMUL rounds.
#[inline(always)]
unsafe fn reduce128(lo: __m128i, hi: __m128i) -> __m128i {
    unsafe {
        let poly = _mm_set_epi64x(0, 0x87);

        // Round 1: hi · R — at most 135 bits.
        let t_lo = _mm_clmulepi64_si128(hi, poly, 0x00);
        let t_hi = _mm_clmulepi64_si128(hi, poly, 0x01);
        let folded_lo = _mm_xor_si128(t_lo, _mm_slli_si128(t_hi, 8));
        let overflow = _mm_srli_si128(t_hi, 8); // ≤ 7 bits at [128..135]
        let r1 = _mm_xor_si128(lo, folded_lo);

        // Round 2: overflow · R — at most 14 bits, no further reduction.
        let t2 = _mm_clmulepi64_si128(overflow, poly, 0x00);
        _mm_xor_si128(r1, t2)
    }
}

#[inline(always)]
unsafe fn load(x: u128) -> __m128i {
    unsafe { _mm_set_epi64x((x >> 64) as i64, x as i64) }
}

#[inline(always)]
unsafe fn extract(x: __m128i) -> u128 {
    unsafe {
        let lo = _mm_cvtsi128_si64(x) as u64 as u128;
        let hi = _mm_extract_epi64(x, 1) as u64 as u128;
        (hi << 64) | lo
    }
}
