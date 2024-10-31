use mpz_fields::Field;
use serde::{Deserialize, Serialize};

use crate::OLEShare;

/// OLE adjustment offset.
#[derive(Debug, Serialize, Deserialize)]
pub struct Offset<F>(pub F);

/// OLE adjustment protocol.
///
/// This is an implementation of <https://crypto.stackexchange.com/questions/100634/converting-a-random-ole-oblivious-linear-function-evaluation-to-an-ole>.
#[derive(Debug)]
pub struct Adjust<F> {
    target: F,
    share: OLEShare<F>,
}

impl<F> Adjust<F>
where
    F: Field,
{
    pub(crate) fn new(target: F, share: OLEShare<F>) -> Self {
        Self { target, share }
    }

    /// Returns adjustment offset.
    pub fn offset(&self) -> Offset<F> {
        Offset(self.share.mul + self.target)
    }

    /// Finishes the adjustment as the OLE sender.
    pub fn sender_finish(self, offset: Offset<F>) -> OLEShare<F> {
        let Offset(offset) = offset;
        let OLEShare { add, mul } = self.share;

        OLEShare {
            add: add - mul * offset,
            mul: self.target,
        }
    }

    /// Finishes the adjustment as the OLE receiver.
    pub fn receiver_finish(self, offset: Offset<F>) -> OLEShare<F> {
        let Offset(offset) = offset;
        let OLEShare { add, .. } = self.share;

        OLEShare {
            add: add + offset * self.target,
            mul: self.target,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test::{assert_ole, role_shares};

    use super::*;
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_adjust_p256() {
        test_adjust::<P256>();
    }

    #[test]
    fn test_adjust_gf2_128() {
        test_adjust::<Gf2_128>();
    }

    fn test_adjust<F>()
    where
        F: Field,
    {
        let mut rng = StdRng::seed_from_u64(0);

        let (sender_share, receiver_share) = role_shares::<F, _>(&mut rng);

        let target_sender_input = F::rand(&mut rng);
        let target_receiver_input = F::rand(&mut rng);

        let sender_adjust = sender_share.adjust(target_sender_input);
        let receiver_adjust = receiver_share.adjust(target_receiver_input);

        let sender_offset = sender_adjust.offset();
        let receiver_offset = receiver_adjust.offset();

        let sender_share = sender_adjust.sender_finish(receiver_offset);
        let receiver_share = receiver_adjust.receiver_finish(sender_offset);

        assert_eq!(sender_share.mul, target_sender_input);
        assert_eq!(receiver_share.mul, target_receiver_input);
        assert_ole(sender_share, receiver_share);
    }
}
