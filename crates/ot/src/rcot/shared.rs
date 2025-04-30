//! Shared RCOT.

mod receiver;
mod sender;

pub use receiver::{SharedRCOTReceiver, SharedRCOTReceiverError};
pub use sender::{SharedRCOTSender, SharedRCOTSenderError};

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{ideal::rcot::ideal_rcot, test::test_rcot};

    use super::*;

    #[tokio::test]
    async fn test_shared_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 8;
        let cycles = 4;

        let (ideal_send, ideal_recv) = ideal_rcot(Block::random(&mut rng), Block::random(&mut rng));

        let sender = SharedRCOTSender::new(ideal_send);
        let receiver = SharedRCOTReceiver::new(ideal_recv);

        let mut senders = vec![sender];
        let mut receivers = vec![receiver];
        for _ in 1..n {
            senders.push(senders[0].clone());
            receivers.push(receivers[0].clone());
        }

        // Drop a pair to make sure it is adaptive.
        senders.pop();
        receivers.pop();

        let tasks: Vec<_> = senders
            .into_iter()
            .zip(receivers)
            .map(|(send, recv)| tokio::spawn(test_rcot(send, recv, 128, cycles)))
            .collect();

        for task in tasks {
            task.await.unwrap();
        }
    }
}
