//! Bit-spread primitive for GF(2^n) squaring.
//!
//! In characteristic 2, `(Σ aᵢ xⁱ)² = Σ aᵢ x^(2i)` — squaring a
//! polynomial is exactly "spread each bit to twice its index". For
//! modern x86 this beats PCLMUL-based squaring even though CLMUL is
//! hardware-accelerated: the 5-round shift/mask chain is all
//! single-cycle ops with excellent ILP, whereas dependent CLMULs pay
//! their 7-cycle latency serially.

/// Spreads a `u32`'s bits into a `u64` with one zero between each bit.
/// Bit `i` of input ends up at position `2i` of output.
#[inline(always)]
pub(crate) fn bit_spread_u32(x: u32) -> u64 {
    let mut x = x as u64;
    x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
    x = (x | (x << 8)) & 0x00FF_00FF_00FF_00FF;
    x = (x | (x << 4)) & 0x0F0F_0F0F_0F0F_0F0F;
    x = (x | (x << 2)) & 0x3333_3333_3333_3333;
    x = (x | (x << 1)) & 0x5555_5555_5555_5555;
    x
}
