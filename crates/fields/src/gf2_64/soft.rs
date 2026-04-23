//! Portable software backend for GF(2⁶⁴) — uses BearSSL-style
//! constant-time `bmul64_full` to avoid schoolbook's per-bit loop, and
//! amortises reduction across the inner-product accumulator.

use crate::bmul::bmul64_full;

use super::Gf2_64;

#[inline]
pub(super) fn mul(a: u64, b: u64) -> u64 {
    let (lo, hi) = bmul64_full(a, b);
    reduce64(lo, hi)
}

/// Multiplicative inverse via Fermat's little theorem.
#[inline]
pub(super) fn inverse(a: u64) -> u64 {
    let mut y = mul(a, a);
    let mut out = y;
    for _ in 2..64 {
        y = mul(y, y);
        out = mul(out, y);
    }
    out
}

#[inline]
pub(super) fn inner_product(a: &[Gf2_64], b: &[Gf2_64]) -> u64 {
    let mut acc_lo = 0u64;
    let mut acc_hi = 0u64;
    for (x, y) in a.iter().zip(b.iter()) {
        let (lo, hi) = bmul64_full(x.0, y.0);
        acc_lo ^= lo;
        acc_hi ^= hi;
    }
    reduce64(acc_lo, acc_hi)
}

/// Reduce a 128-bit polynomial `hi·2⁶⁴ + lo` modulo
/// p(x) = x⁶⁴ + x⁴ + x³ + x + 1 (so `x⁶⁴ ≡ R = x⁴ + x³ + x + 1`).
///
/// First round folds `hi · R` (≤ 68 bits) back; overflow from the shifts is
/// at most 4 bits and is folded once more (its `· R` fits in 8 bits).
#[inline(always)]
fn reduce64(lo: u64, hi: u64) -> u64 {
    // Low 64 bits of `hi · R`: the shifts just drop the top bits.
    let folded_lo = hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    // Bits shifted past position 64 — at most 4 bits, at positions [0..4].
    //   from <<1: bit 63 of hi → overflow bit 0
    //   from <<3: bits 61..63 → overflow bits 0..2
    //   from <<4: bits 60..63 → overflow bits 0..3
    let overflow = (hi >> 63) ^ (hi >> 61) ^ (hi >> 60);
    // `overflow · R` has ≤ 8 bits; no further reduction needed.
    let overflow_folded = overflow ^ (overflow << 1) ^ (overflow << 3) ^ (overflow << 4);
    lo ^ folded_lo ^ overflow_folded
}
