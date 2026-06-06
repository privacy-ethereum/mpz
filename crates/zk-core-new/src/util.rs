
use mpz_fields::gf2_64::Gf2_64;

#[inline]
pub(crate) fn set_lsb(g: &mut Gf2_64, bit: bool) {
    *g = Gf2_64::new((g.to_inner() & !1) | u64::from(bit));
}
