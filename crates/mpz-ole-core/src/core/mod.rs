//! This implementation uses the COPEe protocol from <https://eprint.iacr.org/2016/505> page 10.
//!
//! We use this construction to implement oblivious linear function evaluation (OLE) instead of
//! vector OLE (VOLE), which means that we do not use PRGs, i.e. Extend can only be called once.                                                  
//!                                                                                       
//! Note that this is an OLE with errors implementation. The sender can introduce additive errors.
//! Input privacy is guaranteed, but output privacy is not, when `0` is chosen as an input value.

mod receiver;
mod sender;

pub(crate) use receiver::{ReceiverAdjust, ReceiverShare};
pub(crate) use sender::{SenderAdjust, SenderShare};

use mpz_fields::Field;

/// Workaround because of feature `generic_const_exprs` not available in stable.
///
/// This is used to check at compile-time that the correct const-generic implementation is used for
/// a specific field.
struct Check<const N: usize, F: Field>(std::marker::PhantomData<F>);

impl<const N: usize, F: Field> Check<N, F> {
    const IS_BITSIZE_CORRECT: () = assert!(
        N as u32 == F::BIT_SIZE,
        "Wrong bit size used for field. You need to use `F::BIT_SIZE` for N."
    );
}

/// The masked input of the sender.
///
/// This is the correlation which is sent to the receiver and hides the sender's input.
pub struct MaskedInput<const N: usize, F>([F; N]);

/// The exchange field element for share adjustment.
///
/// This needs to be sent to each other in order to complete the share adjustment.
pub struct ShareAdjust<F>(F);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::create_rot;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, Field, UniformRand};
    use rand::SeedableRng;

    #[test]
    fn test_ole_core() {
        let mut rng = Prg::from_seed(Block::ZERO);

        let sender_input = P256::rand(&mut rng);
        let receiver_input = P256::rand(&mut rng);

        let (sender_share, receiver_share) =
            create_ole::<256, 32, P256>(sender_input, receiver_input);

        let a = sender_input;
        let b = receiver_input;
        let x = sender_share.inner();
        let y = receiver_share.inner();

        assert_eq!(y, a * b + x);
    }

    #[test]
    fn test_ole_adjust() {
        let mut rng = Prg::from_seed(Block::ZERO);

        let sender_input = P256::rand(&mut rng);
        let receiver_input = P256::rand(&mut rng);

        let sender_target = P256::rand(&mut rng);
        let receiver_target = P256::rand(&mut rng);

        let (sender_share, receiver_share) =
            create_ole::<256, 32, P256>(sender_input, receiver_input);

        let (sender_adjust, s_to_r_adjust) = sender_share.adjust(sender_target);
        let (receiver_adjust, r_to_s_adjust) = receiver_share.adjust(receiver_target);

        let sender_share_adjusted = sender_adjust.finish(r_to_s_adjust);
        let receiver_share_adjusted = receiver_adjust.finish(s_to_r_adjust);

        let a = sender_target;
        let b = receiver_target;
        let x = sender_share_adjusted.inner();
        let y = receiver_share_adjusted.inner();

        assert_eq!(y, a * b + x);
    }

    // Unergonomic API because of lack of proper const generic support
    // N should be BIT_SIZE of F
    // K should be BYTE_SIZE of F
    fn create_ole<const N: usize, const K: usize, F: Field>(
        sender_input: F,
        receiver_input: F,
    ) -> (SenderShare<F>, ReceiverShare<F>) {
        let receiver_input_vec = vec![receiver_input];

        let (ot_messages, ot_message_choices) = create_rot::<K, F>(receiver_input_vec);

        let ot_messages: [[F; 2]; N] = ot_messages.try_into().unwrap();
        let ot_message_choices: [F; N] = ot_message_choices.try_into().unwrap();
        let ot_choice = receiver_input;

        let (sender_share, correlation) = SenderShare::new(sender_input, ot_messages);
        let receiver_share = ReceiverShare::new(ot_choice, ot_message_choices, correlation);

        (sender_share, receiver_share)
    }
}
