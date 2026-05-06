//! Shared helpers used by both prover and verifier.

use mpz_fields::gf2_128::Gf2_128;

/// Sets the LSB of `g` to `bit` (pointer-bit convention).
#[inline]
pub(crate) fn set_lsb(g: &mut Gf2_128, bit: bool) {
    *g = Gf2_128::new((g.to_inner() & !1) | u128::from(bit));
}
