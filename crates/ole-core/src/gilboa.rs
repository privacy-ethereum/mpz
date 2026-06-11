//! Semi-honest OLE via Gilboa's OT-based multiplication.
//!
//! Realizes (random) OLE over a field `F` by bit-decomposing the inputs and
//! consuming `F::BIT_SIZE` random OTs per OLE (Gilboa, CRYPTO'99): one ROT per
//! bit, the sender's masked correlations weighted by `2^i` to recover an
//! additive sharing of the product `a·b`. Semi-honest only.

mod receiver;
mod sender;

pub use receiver::{Receiver, ReceiverError};
pub use sender::{Sender, SenderError};

use hybrid_array::Array;
use itybity::ToBits;
use mpz_fields::Field;
use serde::{Deserialize, Serialize};

use crate::OLEShare;

impl<F> OLEShare<F>
where
    F: Field,
{
    /// Creates a new OLE share for the sender.
    ///
    /// # Arguments
    ///
    /// * `input` - Input value, `a`.
    /// * `masks` - Masks for the correlation.
    #[inline]
    pub(crate) fn new_ole_sender(
        input: F,
        masks: Array<[F; 2], F::BitSize>,
    ) -> (Self, MaskedCorrelation<F>) {
        // Compute additive share, `x`.
        let add = masks
            .as_slice()
            .iter()
            .enumerate()
            .fold(F::zero(), |acc, (i, &[zero, _])| {
                acc + F::two_pow(i as u32) * zero
            });

        let share = Self {
            // Sender negates their additive share.
            add: -add,
            mul: input,
        };

        let masked = MaskedCorrelation(Array::from_fn(|i| {
            let [zero, one] = masks[i];
            zero - one + input
        }));

        (share, masked)
    }

    /// Creates a new OLE share for the receiver.
    ///
    /// # Arguments
    ///
    /// * `input` - Input value, `b`.
    /// * `masks` - Chosen correlation masks.
    /// * `corr` - Masked correlation from the sender.
    #[inline]
    pub(crate) fn new_ole_receiver(
        input: F,
        masks: Array<F, F::BitSize>,
        corr: MaskedCorrelation<F>,
    ) -> Self {
        let delta_i = input.iter_lsb0();
        let t_delta_i = masks.iter();
        let corr = corr.0.iter();

        // Compute additive share, `y`.
        let add = delta_i.zip(corr).zip(t_delta_i).enumerate().fold(
            F::zero(),
            |acc, (i, ((delta, &u), &t))| {
                let delta = if delta { F::one() } else { F::zero() };
                acc + F::two_pow(i as u32) * (delta * u + t)
            },
        );

        Self { add, mul: input }
    }
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize)]
pub struct SenderMasks<F: Field> {
    pub masks: Vec<MaskedCorrelation<F>>,
}

/// Masked correlation of the sender.
///
/// This is the correlation which is sent to the receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct MaskedCorrelation<F: Field>(pub(crate) Array<F, F::BitSize>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ROLEReceiver, ROLEReceiverOutput, ROLESender, ROLESenderOutput, test::assert_ole};
    use mpz_core::Block;
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};
    use mpz_ot_core::{
        ideal::rot::IdealROT,
        rot::{AnyReceiver, AnySender},
    };
    use rand::{SeedableRng, distr::StandardUniform, prelude::Distribution, rngs::StdRng};

    #[test]
    fn test_ole_p256() {
        test_ole::<P256>();
    }

    #[test]
    fn test_ole_gf2_128() {
        test_ole::<Gf2_128>();
    }

    fn test_ole<F: Field>()
    where
        StandardUniform: Distribution<F>,
    {
        let count = 8;
        let mut rng = StdRng::seed_from_u64(0);
        let ideal_rot = IdealROT::new(Block::random(&mut rng));

        let rot_sender = AnySender::new(ideal_rot.clone());
        let rot_receiver = AnyReceiver::new(ideal_rot);

        let (mut sender, mut receiver) = (
            Sender::<_, F>::new(Block::random(&mut rng), rot_sender),
            Receiver::<_, F>::new(rot_receiver),
        );

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        assert!(sender.wants_send());
        assert!(receiver.wants_recv());

        sender.rot_mut().rot_mut().flush().unwrap();

        let msg = sender.send().unwrap();
        receiver.recv(msg).unwrap();

        assert!(!sender.wants_send());
        assert!(!receiver.wants_recv());
        assert_eq!(sender.available(), count);
        assert_eq!(receiver.available(), count);

        let ROLESenderOutput {
            id: sender_id,
            shares: sender_shares,
        } = sender.try_send_role(8).unwrap();
        let ROLEReceiverOutput {
            id: receiver_id,
            shares: receiver_shares,
        } = receiver.try_recv_role(8).unwrap();

        assert_eq!(sender_id, receiver_id);
        sender_shares
            .into_iter()
            .zip(receiver_shares)
            .for_each(|(s, r)| {
                assert_ole(s, r);
            })
    }
}
