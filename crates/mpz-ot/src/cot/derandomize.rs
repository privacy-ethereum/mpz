mod receiver;
mod sender;

pub use receiver::{DerandCOTReceiver, DerandCOTReceiverError};
pub use sender::{DerandCOTSender, DerandCOTSenderError};

#[cfg(test)]
mod tests {
    use crate::test::test_cot;

    use super::*;
    use crate::ideal::rcot::ideal_rcot;
    use mpz_core::Block;
    use rand::{rngs::StdRng, SeedableRng};

    #[tokio::test]
    async fn test_derandomize_cot() {
        let mut rng = StdRng::seed_from_u64(0);

        let (ideal_sender, ideal_receiver) =
            ideal_rcot(Block::random(&mut rng), Block::random(&mut rng));

        let sender = DerandCOTSender::new(ideal_sender);
        let receiver = DerandCOTReceiver::new(ideal_receiver);

        test_cot(sender, receiver, 8).await;
    }
}
