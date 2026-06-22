use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use rand_core::RngCore;
use zerocopy::IntoBytes;

#[inline]
pub(crate) fn set_lsb(g: &mut Gf2_128, bit: bool) {
    *g = Gf2_128::new((g.to_inner() & !1) | u128::from(bit));
}

/// Least-significant bit of a wire: the pointer-bit witness value.
#[inline]
pub(crate) fn lsb(g: Gf2_128) -> Gf2 {
    Gf2(g.to_inner() & 1 == 1)
}

/// Draws the next 16-byte challenge weight from a streamed challenge.
///
/// Each multiplication and each polynomial constraint consumes one such weight,
/// so callers must keep `rng` positioned to match the gates evaluated.
#[inline]
pub(crate) fn draw_chi(rng: &mut impl RngCore) -> Gf2_128 {
    let mut chi = Gf2_128::new(0);
    rng.fill_bytes(chi.as_mut_bytes());
    chi
}
