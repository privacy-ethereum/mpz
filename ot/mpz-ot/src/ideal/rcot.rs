//! Ideal functionality for random correlated oblivious transfer.

use crate::{OTError, OTSetup, RandomCOTReceiver, RandomCOTSender};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use mpz_common::Context;
use mpz_core::Block;
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;

/// Ideal random OT sender.
#[derive(Debug)]
pub struct IdealRandomCOTSender<T = Block> {
    sender: mpsc::Sender<Vec<[T; 2]>>,
    delta: Block,
    rng: ChaCha12Rng,
}

/// Ideal random OT receiver.
#[derive(Debug)]
pub struct IdealRandomCOTReceiver<T = Block> {
    receiver: mpsc::Receiver<Vec<[T; 2]>>,
    rng: ChaCha12Rng,
}

/// Creates a pair of ideal random COT sender and receiver.
pub fn ideal_random_cot_pair<T: Send + Sync + 'static>(
    seed: [u8; 32],
    delta: Block,
) -> (IdealRandomCOTSender<T>, IdealRandomCOTReceiver<T>) {
    let (sender, receiver) = mpsc::channel(10);

    (
        IdealRandomCOTSender {
            sender,
            delta,
            rng: ChaCha12Rng::from_seed(seed),
        },
        IdealRandomCOTReceiver {
            receiver,
            rng: ChaCha12Rng::from_seed(seed),
        },
    )
}

#[async_trait]
impl<Ctx, T> OTSetup<Ctx> for IdealRandomCOTSender<T>
where
    Ctx: Context,
    T: Send + Sync,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> RandomCOTSender<Ctx, Block> for IdealRandomCOTSender<Block> {
    async fn send_random_correlated(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<Vec<Block>, OTError> {
        let low = (0..count)
            .map(|_| Block::random(&mut self.rng))
            .collect::<Vec<_>>();

        self.sender
            .try_send(
                low.iter()
                    .map(|msg| [*msg, *msg ^ self.delta])
                    .collect::<Vec<_>>(),
            )
            .expect("IdealRandomCOTSender should be able to send");

        Ok(low)
    }
}

#[async_trait]
impl<Ctx, T> OTSetup<Ctx> for IdealRandomCOTReceiver<T>
where
    Ctx: Context,
    T: Send + Sync,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> RandomCOTReceiver<Ctx, bool, Block> for IdealRandomCOTReceiver<Block> {
    async fn receive_random_correlated(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<(Vec<bool>, Vec<Block>), OTError> {
        let payload = self
            .receiver
            .next()
            .await
            .expect("IdealRandomCOTSender should send a value");

        assert_eq!(payload.len(), count);

        let choices = (0..count).map(|_| self.rng.gen()).collect::<Vec<bool>>();
        let payload = payload
            .into_iter()
            .zip(&choices)
            .map(|(v, c)| {
                let [low, high] = v;
                if *c {
                    high
                } else {
                    low
                }
            })
            .collect();

        Ok((choices, payload))
    }
}

#[cfg(test)]
mod tests {
    use mpz_common::executor::test_st_executor;

    use super::*;

    // Test that the sender and receiver can be used to send and receive values
    #[tokio::test]
    async fn test_ideal_random_cot_owned() {
        let seed = [0u8; 32];
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);

        let delta = Block::from([42u8; 16]);
        let (mut sender, mut receiver) = ideal_random_cot_pair::<Block>(seed, delta);

        let values = sender
            .send_random_correlated(&mut ctx_sender, 8)
            .await
            .unwrap();

        let (choices, received) = receiver
            .receive_random_correlated(&mut ctx_receiver, 8)
            .await
            .unwrap();

        let expected = values
            .into_iter()
            .zip(choices)
            .map(|(v, c)| if c { v ^ delta } else { v })
            .collect::<Vec<_>>();

        assert_eq!(received, expected);
    }
}
