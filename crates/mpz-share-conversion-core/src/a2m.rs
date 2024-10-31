//! A2M conversion protocol.
//!
//! Let `A` be an element of some finite field with `A = x + y`, where `x` is
//! only known to Alice and `y` is only known to Bob. A is unknown to both
//! parties and it is their goal that each of them ends up with a multiplicative
//! share of A. So both parties start with `x` and `y` and want to end up with
//! `a` and `b`, where `A = x + y = a * b`.
//!
//! This module implements the A2M protocol from <https://eprint.iacr.org/2023/964>, page 40,
//! figure 16, 4.

use mpz_fields::Field;
use mpz_ole_core::{OLEShare, Offset};
use serde::{Deserialize, Serialize};

/// Masked share for the A2M conversion.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct A2MMasked<F>(F);

/// Start state for A2M sender.
///
/// We start with a ROLE, where the receiver needs to derandomize
/// their input.
#[derive(Debug)]
pub(crate) struct A2MSenderDerand<F> {
    input: F,
    add: F,
    mul: F,
}

impl<F> A2MSenderDerand<F>
where
    F: Field,
{
    pub(crate) fn new(input: F, role: OLEShare<F>) -> Self {
        Self {
            input,
            add: role.add,
            mul: role.mul,
        }
    }

    /// Receives the receiver's offset.
    pub(crate) fn offset(self, offset: Offset<F>) -> A2MSenderAdjust<F> {
        A2MSenderAdjust {
            input: self.input,
            add: self.add + self.mul * offset.0,
            mul: self.mul,
        }
    }
}

/// A2M Sender sends masked share to the receiver.
#[derive(Debug)]
pub(crate) struct A2MSenderAdjust<F> {
    input: F,
    add: F,
    mul: F,
}

impl<F> A2MSenderAdjust<F>
where
    F: Field,
{
    /// Sends the masked share to the receiver.
    ///
    /// Returns the multiplicative share and masked share, respectively.
    pub(crate) fn send(self) -> Result<(F, A2MMasked<F>), A2MError> {
        let masked = (self.input * self.mul) + self.add;
        let output = self.mul.inverse().ok_or(A2MError { _private: () })?;

        Ok((output, A2MMasked(masked)))
    }
}

/// Start state for A2M receiver.
///
/// We start with a ROLE and derandomize the receiver's input.
#[derive(Debug)]
pub(crate) struct A2MReceiverDerand<F> {
    input: F,
    add: F,
    mul: F,
}

impl<F> A2MReceiverDerand<F>
where
    F: Field,
{
    pub(crate) fn new(input: F, role: OLEShare<F>) -> Self {
        Self {
            input,
            add: role.add,
            mul: role.mul,
        }
    }

    /// Sends the offset to the sender.
    pub(crate) fn offset(self) -> (A2MReceiverAdjust<F>, Offset<F>) {
        let offset = self.input - self.mul;

        (A2MReceiverAdjust { add: self.add }, Offset(offset))
    }
}

/// A2M Receiver receives the masked share.
#[derive(Debug)]
pub(crate) struct A2MReceiverAdjust<F> {
    add: F,
}

impl<F> A2MReceiverAdjust<F>
where
    F: Field,
{
    /// Receives the masked share, returning the multiplicative share.
    pub(crate) fn receive(self, masked: A2MMasked<F>) -> F {
        self.add + masked.0
    }
}

#[derive(Debug, thiserror::Error)]
#[error("A2M error, sender's OLE input is zero")]
pub(crate) struct A2MError {
    _private: (),
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};
    use mpz_ole_core::test::role_shares;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_a2m_p256() {
        test_a2m::<P256>();
    }

    #[test]
    fn test_a2m_gf2_128() {
        test_a2m::<Gf2_128>();
    }

    fn test_a2m<F: Field>() {
        let mut rng = StdRng::seed_from_u64(0);

        let sender_input = F::rand(&mut rng);
        let receiver_input = F::rand(&mut rng);
        let (sender_role, receiver_role) = role_shares(&mut rng);

        let sender = A2MSenderDerand::new(sender_input, sender_role);
        let receiver = A2MReceiverDerand::new(receiver_input, receiver_role);

        let (receiver, offset) = receiver.offset();
        let sender = sender.offset(offset);

        // Check that OLE is derandomized correctly.
        assert_eq!(sender.mul * receiver_input, sender.add + receiver.add);

        let (sender_output, masked) = sender.send().unwrap();
        let receiver_output = receiver.receive(masked);

        assert_eq!(
            sender_output * receiver_output,
            sender_input + receiver_input
        );
    }
}
