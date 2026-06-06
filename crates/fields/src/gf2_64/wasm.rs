//! WASM `simd128` backend for GF(2⁶⁴).
//!
//! Uses `bmul_simd::bmul64_full` (v128-parallelised BearSSL) for the
//! 64×64 carry-less product, then reduces mod p(x) = x⁶⁴+x⁴+x³+x+1
//! with the same shift/XOR chain as the soft backend. `inner_product`
//! keeps its accumulator in a v128 across the whole loop, amortising
//! both the reduction *and* the final bit-reverse+shift.

use std::arch::wasm32::*;

use crate::bmul_simd::{bit_spread_v128, bmul64_full, bmul64_lo_v128, rev64};

#[inline]
pub(super) fn mul(a: u64, b: u64) -> u64 {
    let (lo, hi) = bmul64_full(a, b);
    reduce64(lo, hi)
}

/// Squaring via parallel bit-spread. In char 2,
/// `(Σ aᵢ xⁱ)² = Σ aᵢ x^(2i)`. Pack the low and high 32-bit halves of
/// `a` into the two v128 lanes and run the 32→64 bit-spread on both
/// simultaneously — no multiplies at all.
#[inline]
pub(super) fn square(a: u64) -> u64 {
    let v = bit_spread_v128(u64x2(a as u32 as u64, (a >> 32) as u64));
    let lo = u64x2_extract_lane::<0>(v);
    let hi = u64x2_extract_lane::<1>(v);
    reduce64(lo, hi)
}

/// Deferred accumulator: the raw v128 partial of the 128-bit carry-less
/// sum (lane 0 = lo, lane 1 = bit-reversed hi-raw). The lane 1 → hi
/// conversion (rev64 + shift) is linear, so it commutes with XOR
/// accumulation; recovery and reduction both defer to `finish`.
pub(super) type Acc = v128;

#[inline]
pub(super) fn acc_zero() -> Acc {
    u64x2_splat(0)
}

/// Accumulates the raw v128 partial of `a · b` without recovery or
/// reduction.
#[inline]
pub(super) fn fma(acc: &mut Acc, a: u64, b: u64) {
    let v = bmul64_lo_v128(u64x2(a, rev64(a)), u64x2(b, rev64(b)));
    *acc = v128_xor(*acc, v);
}

/// One-time recovery + reduction of the accumulated sum.
#[inline]
pub(super) fn finish(acc: Acc) -> u64 {
    let lo = u64x2_extract_lane::<0>(acc);
    let hi = rev64(u64x2_extract_lane::<1>(acc)) >> 1;
    reduce64(lo, hi)
}

#[inline]
pub(super) fn inverse(a: u64) -> u64 {
    let mut y = square(a);
    let mut out = y;
    for _ in 2..64 {
        y = square(y);
        out = mul(out, y);
    }
    out
}

/// Reduce a 128-bit polynomial `hi·2⁶⁴ + lo` modulo
/// p(x) = x⁶⁴ + x⁴ + x³ + x + 1 (so `x⁶⁴ ≡ R = x⁴+x³+x+1`).
#[inline(always)]
fn reduce64(lo: u64, hi: u64) -> u64 {
    let folded_lo = hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    let overflow = (hi >> 63) ^ (hi >> 61) ^ (hi >> 60);
    let overflow_folded = overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
    lo ^ folded_lo ^ overflow_folded
}
