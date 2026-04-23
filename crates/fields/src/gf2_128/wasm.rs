//! WASM `simd128` backend for GF(2¹²⁸).
//!
//! Uses `bmul_simd::bmul128_full` (four `bmul64_full`s, each of which
//! runs its forward and reversed halves in v128 parallel), then reduces
//! mod p(x) = x¹²⁸+x⁷+x²+x+1 with the same shift/XOR chain as the soft
//! backend.

use crate::bmul_simd::bmul128_full;

use super::Gf2_128;

#[inline]
pub(super) fn mul(a: u128, b: u128) -> u128 {
    let (lo, hi) = bmul128_full(a, b);
    reduce128(lo, hi)
}

#[inline]
pub(super) fn inner_product(a: &[Gf2_128], b: &[Gf2_128]) -> u128 {
    let mut acc_lo = 0u128;
    let mut acc_hi = 0u128;
    for (x, y) in a.iter().zip(b.iter()) {
        let (lo, hi) = bmul128_full(x.0, y.0);
        acc_lo ^= lo;
        acc_hi ^= hi;
    }
    reduce128(acc_lo, acc_hi)
}

#[inline]
pub(super) fn inverse(a: u128) -> u128 {
    let mut y = mul(a, a);
    let mut out = y;
    for _ in 2..128 {
        y = mul(y, y);
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
