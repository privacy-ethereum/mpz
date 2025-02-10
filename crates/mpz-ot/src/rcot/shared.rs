//! Shared RCOT.

mod receiver;
mod sender;

pub use receiver::{SharedRCOTReceiver, SharedRCOTReceiverError};
pub use sender::{SharedRCOTSender, SharedRCOTSenderError};

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{ideal::rcot::ideal_rcot, test::test_rcot};

    use super::*;

    #[tokio::test]
    async fn test_shared_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 8;
        let cycles = 4;

        let (ideal_send, ideal_recv) = ideal_rcot(Block::random(&mut rng), Block::random(&mut rng));

        let rcots: Vec<_> = SharedRCOTSender::new(n, ideal_send)
            .zip(SharedRCOTReceiver::new(n, ideal_recv))
            .collect();

        assert_eq!(rcots.len(), 8);

        let tasks: Vec<_> = rcots
            .into_iter()
            .map(|(send, recv)| tokio::spawn(test_rcot(send, recv, cycles)))
            .collect();

        for task in tasks {
            task.await.unwrap();
        }
    }
}
