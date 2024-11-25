//! Oblivious linear evaluation core library.
//!
//! This library provides the core functionality for oblivious linear evaluation
//! (OLE). OLE is a 2-party functionality defined as follows:
//!
//! - The sender defines a linear function `y = ab + x` and sends `a` and `x` to
//!   the functionality.
//! - The receiver sends their input `b` to the functionality.
//! - The functionality computes `y = ab + x` and returns `y` to the receiver.
//!
//! It's often easier to frame OLE as producing an additive sharing of a
//! product, where the sender knows `(a, x)` and the receiver knows `(b, y)` such
//! that `ab = x + y`. This representation is used in [`OLEShare`].

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

mod adjust;
#[cfg(any(test, feature = "test-utils"))]
pub mod ideal;
mod receiver;
mod role;
mod sender;
#[cfg(any(test, feature = "test-utils"))]
pub mod test;

pub use adjust::{Adjust, Offset};
pub use receiver::{Receiver, ReceiverError};
pub use role::{ROLEReceiver, ROLEReceiverOutput, ROLESender, ROLESenderOutput};
pub use sender::{Sender, SenderError};

use hybrid_array::Array;
use itybity::ToBits;
use mpz_fields::Field;
use serde::{Deserialize, Serialize};

/// An OLE identifier.
///
/// Multiple OLEs may be batched together under the same ID.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct OLEId(u64);

impl std::fmt::Display for OLEId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OleId({})", self.0)
    }
}

impl OLEId {
    /// Returns the current ID, incrementing `self` in-place.
    pub(crate) fn next(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }
}

/// Share of an OLE.
#[derive(Debug, Clone, Copy)]
pub struct OLEShare<F> {
    /// Additive share.
    pub add: F,
    /// Multiplicative share.
    pub mul: F,
}

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

    /// Adjusts the multiplicative share to the target.
    pub fn adjust(self, target: F) -> Adjust<F> {
        Adjust::new(target, self)
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
    use mpz_core::Block;
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};
    use mpz_ot_core::{
        ideal::rot::IdealROT,
        rot::{AnyReceiver, AnySender},
    };
    use rand::{distributions::Standard, prelude::Distribution, rngs::StdRng, SeedableRng};
    use test::assert_ole;

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
        Standard: Distribution<F>,
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
