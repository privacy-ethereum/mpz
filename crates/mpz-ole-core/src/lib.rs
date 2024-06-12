//! Implementations of Oblivious Linear Function Evaluation (OLE).
//!
//! Core logic of the protocol without I/O.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

pub mod ideal;

pub mod core;
pub mod msg;
mod receiver;
mod sender;

pub use receiver::{BatchReceiverAdjust, OLEReceiver};
pub use sender::{BatchSenderAdjust, OLESender};
use serde::{Deserialize, Serialize};

/// An OLE transfer identifier.
///
/// Multiple transfers may be batched together under the same transfer ID.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct TransferId(u64);

impl std::fmt::Display for TransferId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransferId({})", self.0)
    }
}

impl TransferId {
    /// Returns the current transfer ID, incrementing `self` in-place.
    pub(crate) fn next(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }
}

/// An error for OLE
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum OLEError {
    #[error("The number of provided elements do not match. Got {0}, expected {1}")]
    ExpectedMultipleOf(usize, usize),
    #[error("Wrong number of adjustments. Got {0}, expected {1}")]
    UnequalAdjustments(usize, usize),
    #[error("Provided number of masks is incorrect. Got {0}, expected {1}")]
    WrongNumberOfMasks(usize, usize),
    #[error("Got {0}, but expected a multiple of {1}")]
    MultipleOf(usize, usize),
    #[error("Wrong transfer id. Got {0}, expected {1}")]
    WrongId(TransferId, TransferId),
}

#[cfg(test)]
mod tests {
    use crate::{OLEReceiver, OLESender};
    use itybity::ToBits;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use mpz_ot_core::ideal::rot::IdealROT;
    use rand::SeedableRng;

    #[test]
    fn test_ole_sender_receiver_preprocess() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (mut sender, mut receiver) =
            (OLESender::<P256>::default(), OLEReceiver::<P256>::default());

        let sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (ot_messages, ot_message_choices) = create_rot(receiver_input.clone());

        let masked = sender
            .preprocess(sender_input.clone(), ot_messages)
            .unwrap();
        receiver
            .preprocess(receiver_input.clone(), ot_message_choices, masked)
            .unwrap();

        let sender_shares = sender.consume(count).unwrap();
        let receiver_shares = receiver.consume(count).unwrap();

        sender_input
            .iter()
            .zip(receiver_input)
            .zip(sender_shares)
            .zip(receiver_shares)
            .for_each(|(((&a, b), x), y)| assert_eq!(y.inner(), a * b + x.inner()));
    }

    #[test]
    fn test_ole_sender_receiver_adjust() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (mut sender, mut receiver) =
            (OLESender::<P256>::default(), OLEReceiver::<P256>::default());

        let sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (ot_messages, ot_message_choices) = create_rot(receiver_input.clone());

        let masked = sender
            .preprocess(sender_input.clone(), ot_messages)
            .unwrap();
        receiver
            .preprocess(receiver_input.clone(), ot_message_choices, masked)
            .unwrap();

        let sender_targets: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_targets: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (sender_adjust, s_to_r_adjust) = sender.adjust(sender_targets.clone()).unwrap();
        let (receiver_adjust, r_to_s_adjust) = receiver.adjust(receiver_targets.clone()).unwrap();

        let sender_shares_adjusted = sender_adjust.finish_adjust(r_to_s_adjust).unwrap();
        let receiver_shares_adjusted = receiver_adjust.finish_adjust(s_to_r_adjust).unwrap();

        sender_targets
            .iter()
            .zip(receiver_targets)
            .zip(sender_shares_adjusted)
            .zip(receiver_shares_adjusted)
            .for_each(|(((&a, b), x), y)| assert_eq!(y.inner(), a * b + x.inner()));
    }

    pub(crate) fn create_rot(receiver_choices: Vec<P256>) -> (Vec<[P256; 2]>, Vec<P256>) {
        let mut rot = IdealROT::default();
        let receiver_choices: Vec<bool> = receiver_choices.iter_lsb0().collect();
        let (rot_sender, rot_receiver) = rot.random_with_choices::<P256>(receiver_choices);

        let ot_messages: Vec<[P256; 2]> = rot_sender.msgs;
        let ot_message_choices: Vec<P256> = rot_receiver.msgs;

        (ot_messages, ot_message_choices)
    }
}
