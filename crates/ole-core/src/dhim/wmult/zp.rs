//! Arithmetic in `Z_p` for a small prime `p`, over `u64`.
//!
//! All CRT moduli `pᵢ` satisfy `p ≤ 1063 < 2¹¹`, so operands stay well below
//! `2³²`: additions never overflow `u64`.

/// `a − b mod p`. Requires `a, b < p`.
#[inline]
pub(crate) fn sub(a: u64, b: u64, p: u64) -> u64 {
    debug_assert!(a < p && b < p);
    (a + p - b) % p
}

/// `−a mod p`. Requires `a < p`.
#[inline]
pub(crate) fn neg(a: u64, p: u64) -> u64 {
    debug_assert!(a < p);
    if a == 0 { 0 } else { p - a }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference() {
        for &p in &[5u64, 7, 97, 1063] {
            for a in 0..p {
                for b in 0..p {
                    assert_eq!(sub(a, b, p), (a + p - b) % p);
                }
                assert_eq!(neg(a, p), (p - a) % p);
            }
        }
    }
}
