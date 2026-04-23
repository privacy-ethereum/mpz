//! Portable software backend for GF(2¹²⁸) — uses BearSSL-style
//! constant-time `bmul128_full` (four `bmul64_full` calls) to avoid
//! schoolbook's per-bit u128 loop, and amortises reduction across the
//! inner-product accumulator.

use crate::bmul::bmul128_full;

use super::Gf2_128;

#[inline]
pub(super) fn mul(a: u128, b: u128) -> u128 {
    let (lo, hi) = bmul128_full(a, b);
    reduce128(lo, hi)
}

/// Multiplicative inverse via Fermat's little theorem.
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

/// Reduce a 256-bit polynomial `hi·2¹²⁸ + lo` modulo
/// p(x) = x¹²⁸ + x⁷ + x² + x + 1 (so `x¹²⁸ ≡ R = x⁷ + x² + x + 1`).
///
/// First round folds `hi · R` (≤ 135 bits) back; overflow from the shifts
/// is at most 7 bits and is folded once more (its `· R` fits in 14 bits).
#[inline(always)]
fn reduce128(lo: u128, hi: u128) -> u128 {
    // Low 128 bits of `hi · R`: u128 shifts silently drop the top bits.
    let folded_lo = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    // Bits shifted past position 128 — at most 7 bits, at positions [0..7].
    //   from <<1: bit 127 of hi → overflow bit 0
    //   from <<2: bits 126..127 → overflow bits 0..1
    //   from <<7: bits 121..127 → overflow bits 0..6
    let overflow = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    // `overflow · R` has ≤ 14 bits; no further reduction needed.
    let overflow_folded = overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
    lo ^ folded_lo ^ overflow_folded
}
