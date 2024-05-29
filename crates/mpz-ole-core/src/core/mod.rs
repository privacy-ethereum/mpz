//! This implementation is based on the COPEe protocol from <https://eprint.iacr.org/2016/505> page 10
//! with the following modification:
//!
//! - The `Initialize` stage is instantiated using random OT rather than chosen-input OT.
//! - The `Extend` stage can only be called once, since our goal is to implement oblivious linear
//!   function evaluation (OLE) rather than vector OLE (VOLE) (which means that we do not use PRGs).                                                  
//! - The evaluated function is f(b)=a*b+x rather than f(b)=a*b-x.                                                  
//!                                                                                       
//! Note that this is an OLE with errors implementation. A malicious sender is allowed to set its own
//! output and can introduce additive errors into the receiver's output.

mod receiver;
mod sender;

use hybrid_array::Array;
pub use receiver::{ReceiverAdjust, ReceiverShare};
pub use sender::{SenderAdjust, SenderShare};

use mpz_fields::Field;

/// The masked correlation of the sender.
///
/// This is the correlation which is sent to the receiver.
pub struct MaskedCorrelation<F: Field>(pub(crate) Array<F, F::BitSize>);

/// The exchange field element for share adjustment.
///
/// This needs to be sent to each other in order to complete the share adjustment.
#[derive(Debug)]
pub struct ShareAdjust<F>(pub(crate) F);

#[cfg(test)]
mod tests {
    use crate::core::{ReceiverShare, SenderShare};
    use crate::tests::create_rot;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[test]
    fn test_ole_core() {
        let mut rng = Prg::from_seed(Block::ZERO);

        let sender_input = P256::rand(&mut rng);
        let receiver_input = P256::rand(&mut rng);

        let (sender_share, receiver_share) = create_ole(sender_input, receiver_input);

        let a = sender_input;
        let b = receiver_input;
        let x = sender_share.inner();
        let y = receiver_share.inner();

        assert_eq!(y, a * b + x);
    }

    #[test]
    fn test_ole_core_vec() {
        let count = 12;
        let from_seed = Prg::from_seed(Block::ZERO);
        let mut rng = from_seed;

        let sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (ot_messages, ot_message_choices) = create_rot(receiver_input.clone());

        let (sender_shares, masked) =
            SenderShare::new_vec(sender_input.clone(), ot_messages).unwrap();
        let receiver_shares =
            ReceiverShare::new_vec(receiver_input.clone(), ot_message_choices, masked).unwrap();

        sender_input
            .iter()
            .zip(receiver_input)
            .zip(sender_shares)
            .zip(receiver_shares)
            .for_each(|(((&a, b), x), y)| assert_eq!(y.inner(), a * b + x.inner()));
    }

    #[test]
    fn test_ole_adjust() {
        let mut rng = Prg::from_seed(Block::ZERO);

        let sender_input = P256::rand(&mut rng);
        let receiver_input = P256::rand(&mut rng);

        let sender_target = P256::rand(&mut rng);
        let receiver_target = P256::rand(&mut rng);

        let (sender_share, receiver_share) = create_ole(sender_input, receiver_input);

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

    fn create_ole(
        sender_input: P256,
        receiver_input: P256,
    ) -> (SenderShare<P256>, ReceiverShare<P256>) {
        let receiver_input_vec = vec![receiver_input];

        let (ot_messages, ot_message_choices) = create_rot(receiver_input_vec);

        let ot_messages: [[P256; 2]; 256] = ot_messages.try_into().unwrap();
        let ot_message_choices: [P256; 256] = ot_message_choices.try_into().unwrap();
        let ot_choice = receiver_input;

        let (sender_share, correlation) = SenderShare::new(sender_input, ot_messages);
        let receiver_share = ReceiverShare::new(ot_choice, ot_message_choices, correlation);

        (sender_share, receiver_share)
    }
}
