//! Ideal functionality for random oblivious transfer.

use crate::{OTError, OTSetup, RandomOTReceiver, RandomOTSender};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use mpz_common::Context;
use mpz_core::{prg::Prg, Block};
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};

/// Ideal random OT sender.
#[derive(Debug)]
pub struct IdealRandomOTSender<T = Block> {
    sender: mpsc::Sender<Vec<[T; 2]>>,
    rng: ChaCha12Rng,
}

/// Ideal random OT receiver.
#[derive(Debug)]
pub struct IdealRandomOTReceiver<T = Block> {
    receiver: mpsc::Receiver<Vec<[T; 2]>>,
    rng: ChaCha12Rng,
}

/// Creates a pair of ideal random OT sender and receiver.
pub fn ideal_random_ot_pair<T: Send + Sync + 'static>(
    seed: [u8; 32],
) -> (IdealRandomOTSender<T>, IdealRandomOTReceiver<T>) {
    let (sender, receiver) = mpsc::channel(10);

    (
        IdealRandomOTSender {
            sender,
            rng: ChaCha12Rng::from_seed(seed),
        },
        IdealRandomOTReceiver {
            receiver,
            rng: ChaCha12Rng::from_seed(seed),
        },
    )
}

#[async_trait]
impl<Ctx, T> OTSetup<Ctx> for IdealRandomOTSender<T>
where
    Ctx: Context,
    T: Send + Sync,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> RandomOTSender<Ctx, [Block; 2]> for IdealRandomOTSender<Block> {
    async fn send_random(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<Vec<[Block; 2]>, OTError> {
        let messages = (0..count)
            .map(|_| [Block::random(&mut self.rng), Block::random(&mut self.rng)])
            .collect::<Vec<_>>();

        self.sender
            .try_send(messages.clone())
            .expect("IdealRandomOTSender should be able to send");

        Ok(messages)
    }
}

#[async_trait]
impl<Ctx: Context, const N: usize> RandomOTSender<Ctx, [[u8; N]; 2]>
    for IdealRandomOTSender<[u8; N]>
{
    async fn send_random(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<Vec<[[u8; N]; 2]>, OTError> {
        let prng = |block| {
            let mut prg = Prg::from_seed(block);
            let mut out = [0_u8; N];
            prg.fill_bytes(&mut out);
            out
        };

        let messages = (0..count)
            .map(|_| {
                [
                    prng(Block::random(&mut self.rng)),
                    prng(Block::random(&mut self.rng)),
                ]
            })
            .collect::<Vec<_>>();

        self.sender
            .try_send(messages.clone())
            .expect("IdealRandomOTSender should be able to send");

        Ok(messages)
    }
}

#[async_trait]
impl<Ctx, T> OTSetup<Ctx> for IdealRandomOTReceiver<T>
where
    Ctx: Context,
    T: Send + Sync,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> RandomOTReceiver<Ctx, bool, Block> for IdealRandomOTReceiver<Block> {
    async fn receive_random(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<(Vec<bool>, Vec<Block>), OTError> {
        let payload = self
            .receiver
            .next()
            .await
            .expect("IdealRandomOTSender should send a value");

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

#[async_trait]
impl<Ctx: Context, const N: usize> RandomOTReceiver<Ctx, bool, [u8; N]>
    for IdealRandomOTReceiver<[u8; N]>
{
    async fn receive_random(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<(Vec<bool>, Vec<[u8; N]>), OTError> {
        let payload = self
            .receiver
            .next()
            .await
            .expect("IdealRandomOTSender should send a value");

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
    use super::*;
    use mpz_common::executor::test_st_executor;

    #[tokio::test]
    async fn test_ideal_random_ot_owned_block() {
        let seed = [0u8; 32];
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);
        let (mut sender, mut receiver) = ideal_random_ot_pair::<Block>(seed);

        let values = RandomOTSender::send_random(&mut sender, &mut ctx_sender, 8)
            .await
            .unwrap();

        let (choices, received) =
            RandomOTReceiver::receive_random(&mut receiver, &mut ctx_receiver, 8)
                .await
                .unwrap();

        let expected = values
            .into_iter()
            .zip(choices)
            .map(|(v, c)| v[c as usize])
            .collect::<Vec<_>>();

        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn test_ideal_random_ot_owned_array() {
        let seed = [0u8; 32];
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);
        let (mut sender, mut receiver) = ideal_random_ot_pair::<[u8; 64]>(seed);

        let values = RandomOTSender::send_random(&mut sender, &mut ctx_sender, 8)
            .await
            .unwrap();

        let (choices, received) =
            RandomOTReceiver::receive_random(&mut receiver, &mut ctx_receiver, 8)
                .await
                .unwrap();

        let expected = values
            .into_iter()
            .zip(choices)
            .map(|(v, c)| v[c as usize])
            .collect::<Vec<_>>();

        assert_eq!(received, expected);
    }
}
