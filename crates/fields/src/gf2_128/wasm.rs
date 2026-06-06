//! WASM `simd128` backend for GF(2¹²⁸).
//!
//! Uses `bmul_simd::bmul128_full` (four `bmul64_full`s, each of which
//! runs its forward and reversed halves in v128 parallel), then reduces
//! mod p(x) = x¹²⁸+x⁷+x²+x+1 with the same shift/XOR chain as the soft
//! backend.

use std::arch::wasm32::*;

use crate::bmul_simd::{bit_spread_v128, bmul128_full, bmul64_raw, recover_raw};

#[inline]
pub(super) fn mul(a: u128, b: u128) -> u128 {
    let (lo, hi) = bmul128_full(a, b);
    reduce128(lo, hi)
}

/// Squaring via parallel bit-spread. In characteristic 2,
/// `(a_lo + a_hi · x⁶⁴)² = a_lo² + a_hi² · x¹²⁸` — the cross term
/// vanishes. Each half-square is a pure bit-spread of a u64 into a
/// u128. We run two 32→64 spreads per v128, so the whole 256-bit
/// squared polynomial comes from two `bit_spread_v128` calls — zero
/// multiplies.
#[inline]
pub(super) fn square(a: u128) -> u128 {
    let v_lo = bit_spread_v128(u64x2(a as u32 as u64, (a >> 32) as u32 as u64));
    let v_hi = bit_spread_v128(u64x2((a >> 64) as u32 as u64, (a >> 96) as u64));

    let ll = u64x2_extract_lane::<0>(v_lo);
    let lh = u64x2_extract_lane::<1>(v_lo);
    let hl = u64x2_extract_lane::<0>(v_hi);
    let hh = u64x2_extract_lane::<1>(v_hi);

    // a_lo² fills bits [0..128], a_hi² fills bits [128..256].
    let lo = ((lh as u128) << 64) | (ll as u128);
    let hi = ((hh as u128) << 64) | (hl as u128);
    reduce128(lo, hi)
}

/// Deferred accumulator: the three Karatsuba partials (p00, p11, p01^p10)
/// of the 256-bit carry-less sum in BearSSL "raw" v128 form — lane 0 = lo,
/// lane 1 = reversed hi-form. Both parts are linear in GF(2) under XOR, so
/// the per-product Karatsuba merge, the rev64+shift recovery, and the
/// reduction all defer to `finish`.
pub(super) type Acc = (v128, v128, v128);

#[inline]
pub(super) fn acc_zero() -> Acc {
    (u64x2_splat(0), u64x2_splat(0), u64x2_splat(0))
}

/// Accumulates the raw Karatsuba partials of `a · b` without recovery or
/// reduction.
#[inline]
pub(super) fn fma(acc: &mut Acc, a: u128, b: u128) {
    let a_lo = a as u64;
    let a_hi = (a >> 64) as u64;
    let b_lo = b as u64;
    let b_hi = (b >> 64) as u64;

    let p00 = bmul64_raw(a_lo, b_lo);
    let p11 = bmul64_raw(a_hi, b_hi);
    let p01 = bmul64_raw(a_lo, b_hi);
    let p10 = bmul64_raw(a_hi, b_lo);

    acc.0 = v128_xor(acc.0, p00);
    acc.1 = v128_xor(acc.1, p11);
    acc.2 = v128_xor(acc.2, v128_xor(p01, p10));
}

/// One-time recovery + Karatsuba merge + reduction of the accumulated sum.
#[inline]
pub(super) fn finish(acc: Acc) -> u128 {
    let (p00_lo, p00_hi) = recover_raw(acc.0);
    let (p11_lo, p11_hi) = recover_raw(acc.1);
    let (mid_lo, mid_hi) = recover_raw(acc.2);

    let p00 = ((p00_hi as u128) << 64) | (p00_lo as u128);
    let p11 = ((p11_hi as u128) << 64) | (p11_lo as u128);

    let lo = p00 ^ ((mid_lo as u128) << 64);
    let hi = p11 ^ (mid_hi as u128);

    reduce128(lo, hi)
}

#[inline]
pub(super) fn inverse(a: u128) -> u128 {
    let mut y = square(a);
    let mut out = y;
    for _ in 2..128 {
        y = square(y);
        out = mul(out, y);
    }
    out
}

/// Reduce a 256-bit polynomial `hi·2¹²⁸ + lo` modulo
/// p(x) = x¹²⁸ + x⁷ + x² + x + 1 (so `x¹²⁸ ≡ R = x⁷+x²+x+1`).
#[inline(always)]
fn reduce128(lo: u128, hi: u128) -> u128 {
    let folded_lo = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    let overflow = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    let overflow_folded = overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
    lo ^ folded_lo ^ overflow_folded
}
