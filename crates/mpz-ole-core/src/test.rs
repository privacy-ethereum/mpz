//! Test utilities.

use mpz_fields::Field;
use rand::Rng;

use crate::OLEShare;

/// OLE evaluation.
///
/// `ab = x + y`
#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)]
pub struct OLE<F> {
    pub a: F,
    pub b: F,
    pub x: F,
    pub y: F,
}

/// Returns a random OLE.
pub fn role<F: Field, R: Rng + ?Sized>(rng: &mut R) -> OLE<F> {
    let a = F::rand(rng);
    let b = F::rand(rng);
    let x = F::rand(rng);
    let y = (a * b) - x;

    OLE { a, b, x, y }
}

/// Returns random OLE shares.
pub fn role_shares<F: Field, R: Rng + ?Sized>(rng: &mut R) -> (OLEShare<F>, OLEShare<F>) {
    let role = role(rng);

    (
        OLEShare {
            add: role.x,
            mul: role.a,
        },
        OLEShare {
            add: role.y,
            mul: role.b,
        },
    )
}

/// Asserts correctness of OLE.
pub fn assert_ole<F: Field>(sender_share: OLEShare<F>, receiver_share: OLEShare<F>) {
    assert_eq!(
        sender_share.mul * receiver_share.mul,
        sender_share.add + receiver_share.add
    )
}

#[cfg(test)]
mod tests {
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn test_role_fixture_p256() {
        test_role_fixture::<P256>();
    }

    #[test]
    fn test_role_fixture_gf2_128() {
        test_role_fixture::<Gf2_128>();
    }

    fn test_role_fixture<F: Field>() {
        let mut rng = StdRng::seed_from_u64(0);

        let OLE { a, b, x, y } = role::<F, _>(&mut rng);

        assert_eq!(a * b, x + y);
    }

    #[test]
    fn test_role_share_fixture_p256() {
        test_role_share_fixture::<P256>();
    }

    #[test]
    fn test_role_share_fixture_gf2_128() {
        test_role_share_fixture::<Gf2_128>();
    }

    fn test_role_share_fixture<F: Field>() {
        let mut rng = StdRng::seed_from_u64(0);

        let (sender_share, receiver_share) = role_shares::<F, _>(&mut rng);

        assert_ole(sender_share, receiver_share);
    }
}
