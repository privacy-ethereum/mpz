#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

//! Implementations of Oblivious Linear Function Evaluation (OLE).
//! Core logic of the protocol without I/O.
//!
//! We use the COPEe protocol from <https://eprint.iacr.org/2016/505> page 10. We use this
//! construction to implement OLE instead of VOLE, which means that we do not use PRGs, i.e. Extend
//! can only be called once.                                                  
//!                                                                                       
//! Note that this is an OLE with errors implementation. The sender can introduce additive errors.
//! Input privacy is guaranteed, but output privacy is not, when `0` is chosen as an input value.

use mpz_fields::Field;

pub mod ideal;
mod receiver;
mod sender;

pub use receiver::{ReceiverAdjust, ReceiverShare};
pub use sender::{SenderAdjust, SenderShare};

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
    use itybity::{FromBitIterator, ToBits};
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, Field, UniformRand};
    use mpz_ot_core::ideal::rot::IdealROT;
    use rand::SeedableRng;

    #[test]
    fn test_ole() {
        let mut rng = Prg::from_seed(Block::ZERO);

        let sender_input = P256::rand(&mut rng);
        let receiver_input = P256::rand(&mut rng);

        let mut rot = IdealROT::default();
        let (rot_sender, rot_receiver) = rot
            .random_with_choices::<{ P256::BIT_SIZE as usize / 8 }>(
                receiver_input.iter_lsb0().collect(),
            );

        let ot_messages: Vec<[P256; 2]> = rot_sender
            .msgs
            .iter()
            .map(|[a, b]| {
                [
                    P256::from_lsb0_iter(a.iter_lsb0()),
                    P256::from_lsb0_iter(b.iter_lsb0()),
                ]
            })
            .collect();
        let ot_messages: [[P256; 2]; P256::BIT_SIZE as usize] = ot_messages.try_into().unwrap();

        let ot_choice = rot_receiver.choices;
        let ot_choice = P256::from_lsb0_iter(ot_choice.iter_lsb0());

        let ot_choice_messages: Vec<P256> = rot_receiver
            .msgs
            .iter()
            .map(|f| P256::from_lsb0_iter(f.iter_lsb0()))
            .collect();
        let ot_choice_messages: [P256; P256::BIT_SIZE as usize] =
            ot_choice_messages.try_into().unwrap();

        let (sender_share, correlation) = SenderShare::new(sender_input, ot_messages);
        let receiver_share = ReceiverShare::new(ot_choice, ot_choice_messages, correlation);

        let a = sender_input;
        let b = receiver_input;
        let x = sender_share.inner();
        let y = receiver_share.inner();

        assert_eq!(y, a * b + x);
    }
}
