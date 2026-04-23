//! WASM `simd128` carry-less multiplication primitives.
//!
//! Uses the BearSSL bit-interleaving algorithm (the same one as scalar
//! `bmul`) but runs the forward and bit-reversed halves of
//! `bmul64_full` in parallel across the two `u64` lanes of a `v128`,
//! collapsing 32 scalar 64×64 multiplications into 16 `i64x2_mul`s.
//!
//! Since WASM has no carry-less-multiply instruction in `simd128`
//! (neither stable nor relaxed-SIMD), the lane-parallel BearSSL trick
//! is the best acceleration available.

use std::arch::wasm32::*;

/// Returns a `v128` whose lane `i` holds the low-64 carry-less product of
/// `x`'s and `y`'s lane `i`. Both lanes run the BearSSL bit-interleaving
/// algorithm simultaneously via `i64x2_mul`.
#[inline(always)]
pub(crate) fn bmul64_lo_v128(x: v128, y: v128) -> v128 {
    let m0 = u64x2_splat(0x1111_1111_1111_1111);
    let m1 = u64x2_splat(0x2222_2222_2222_2222);
    let m2 = u64x2_splat(0x4444_4444_4444_4444);
    let m3 = u64x2_splat(0x8888_8888_8888_8888);

    let a0 = v128_and(x, m0);
    let a1 = v128_and(x, m1);
    let a2 = v128_and(x, m2);
    let a3 = v128_and(x, m3);
    let b0 = v128_and(y, m0);
    let b1 = v128_and(y, m1);
    let b2 = v128_and(y, m2);
    let b3 = v128_and(y, m3);

    let z0 = v128_xor(
        v128_xor(i64x2_mul(a0, b0), i64x2_mul(a1, b3)),
        v128_xor(i64x2_mul(a2, b2), i64x2_mul(a3, b1)),
    );
    let z1 = v128_xor(
        v128_xor(i64x2_mul(a0, b1), i64x2_mul(a1, b0)),
        v128_xor(i64x2_mul(a2, b3), i64x2_mul(a3, b2)),
    );
    let z2 = v128_xor(
        v128_xor(i64x2_mul(a0, b2), i64x2_mul(a1, b1)),
        v128_xor(i64x2_mul(a2, b0), i64x2_mul(a3, b3)),
    );
    let z3 = v128_xor(
        v128_xor(i64x2_mul(a0, b3), i64x2_mul(a1, b2)),
        v128_xor(i64x2_mul(a2, b1), i64x2_mul(a3, b0)),
    );

    v128_xor(
        v128_xor(v128_and(z0, m0), v128_and(z1, m1)),
        v128_xor(v128_and(z2, m2), v128_and(z3, m3)),
    )
}

/// Bit-reverses a `u64` (scalar — WASM has no bit-reverse instruction).
#[inline(always)]
pub(crate) fn rev64(mut x: u64) -> u64 {
    x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
    x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
    x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
    x.swap_bytes()
}

/// Full 64×64 carry-less product, left in *raw* v128 form. Lane 0 is
/// the low 64 bits of the product; lane 1 is the BearSSL bit-reversed
/// product form (which still needs `rev64(lane1) >> 1` to recover the
/// high 64 bits — see [`recover_raw`]).
///
/// Prefer this over [`bmul64_full`] whenever many partials are going to
/// be XOR-accumulated: since `rev64` and `>> 1` are linear over GF(2),
/// they commute with XOR and can be deferred to the end of the
/// accumulation.
#[inline(always)]
pub(crate) fn bmul64_raw(x: u64, y: u64) -> v128 {
    bmul64_lo_v128(u64x2(x, rev64(x)), u64x2(y, rev64(y)))
}

/// Recover scalar `(lo, hi)` from an accumulated raw v128 bmul partial.
#[inline(always)]
pub(crate) fn recover_raw(v: v128) -> (u64, u64) {
    let lo = u64x2_extract_lane::<0>(v);
    let hi = rev64(u64x2_extract_lane::<1>(v)) >> 1;
    (lo, hi)
}

/// Full 64×64 → 128 bit carry-less product. Returns `(lo, hi)` such that
/// the 128-bit product is `hi·2⁶⁴ + lo`.
#[inline(always)]
pub(crate) fn bmul64_full(x: u64, y: u64) -> (u64, u64) {
    recover_raw(bmul64_raw(x, y))
}

/// Full 128×128 → 256 bit carry-less product. Returns `(lo, hi)` such
/// that the 256-bit product is `hi·2¹²⁸ + lo`.
#[inline(always)]
pub(crate) fn bmul128_full(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a as u64;
    let a_hi = (a >> 64) as u64;
    let b_lo = b as u64;
    let b_hi = (b >> 64) as u64;

    let (p00_lo, p00_hi) = bmul64_full(a_lo, b_lo);
    let (p11_lo, p11_hi) = bmul64_full(a_hi, b_hi);
    let (p01_lo, p01_hi) = bmul64_full(a_lo, b_hi);
    let (p10_lo, p10_hi) = bmul64_full(a_hi, b_lo);

    let mid_lo = p01_lo ^ p10_lo;
    let mid_hi = p01_hi ^ p10_hi;

    let p00 = ((p00_hi as u128) << 64) | (p00_lo as u128);
    let p11 = ((p11_hi as u128) << 64) | (p11_lo as u128);

    let lo = p00 ^ ((mid_lo as u128) << 64);
    let hi = p11 ^ (mid_hi as u128);

    (lo, hi)
}
