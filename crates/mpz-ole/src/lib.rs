//! Oblivious linear evaluation.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

#[cfg(any(test, feature = "test-utils"))]
pub mod ideal;
mod receiver;
mod sender;

pub use mpz_ole_core::{ROLEReceiver, ROLEReceiverOutput, ROLESender, ROLESenderOutput};
pub use receiver::{Receiver, ReceiverError};
pub use sender::{Sender, SenderError};

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_common::{context::test_st_context, Flush};
    use mpz_core::Block;
    use mpz_fields::p256::P256;
    use mpz_ole_core::test::assert_ole;
    use mpz_ot::{
        ideal::rot::ideal_rot,
        rot::any::{AnyReceiver, AnySender},
    };
    use rand::{rngs::StdRng, SeedableRng};
    use sender::Sender;

    #[tokio::test]
    async fn test_role() {
        let (mut ctx_sender, mut ctx_receiver) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let (rot_sender, rot_receiver) = ideal_rot(Block::random(&mut rng));

        let mut sender =
            Sender::<_, P256>::new(Block::random(&mut rng), AnySender::new(rot_sender));
        let mut receiver = Receiver::<_, P256>::new(AnyReceiver::new(rot_receiver));

        let count = 8;
        sender.alloc(8).unwrap();
        receiver.alloc(8).unwrap();

        futures::join!(
            async { sender.flush(&mut ctx_sender).await.unwrap() },
            async { receiver.flush(&mut ctx_receiver).await.unwrap() }
        );

        let ROLESenderOutput {
            id: sender_id,
            shares: sender_shares,
        } = sender.try_send_role(count).unwrap();

        let ROLEReceiverOutput {
            id: receiver_id,
            shares: receiver_shares,
        } = receiver.try_recv_role(count).unwrap();

        assert_eq!(sender_id, receiver_id);
        sender_shares
            .into_iter()
            .zip(receiver_shares)
            .for_each(|(s, r)| {
                assert_ole(s, r);
            });
    }
}
