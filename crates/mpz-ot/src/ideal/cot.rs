//! Ideal functionality for correlated oblivious transfer.

use async_trait::async_trait;

use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Allocate, Context, Preprocess,
};
use mpz_core::Block;
use mpz_ot_core::{
    ideal::cot::IdealCOT, COTReceiverOutput, COTSenderOutput, RCOTReceiverOutput, RCOTSenderOutput,
};

use crate::{
    COTReceiver, COTSender, Correlation, OTError, OTSetup, RandomCOTReceiver, RandomCOTSender,
};

fn cot(
    f: &mut IdealCOT,
    sender_count: usize,
    choices: Vec<bool>,
) -> (COTSenderOutput<Block>, COTReceiverOutput<Block>) {
    assert_eq!(sender_count, choices.len());

    f.correlated(choices)
}

fn rcot(
    f: &mut IdealCOT,
    sender_count: usize,
    receiver_count: usize,
) -> (RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>) {
    assert_eq!(sender_count, receiver_count);

    f.random_correlated(sender_count)
}

/// Returns an ideal COT sender and receiver.
pub fn ideal_cot() -> (IdealCOTSender, IdealCOTReceiver) {
    let (alice, bob) = ideal_f2p(IdealCOT::default());
    (IdealCOTSender(alice), IdealCOTReceiver(bob))
}

/// Returns an ideal random COT sender and receiver.
pub fn ideal_rcot() -> (IdealCOTSender, IdealCOTReceiver) {
    let (alice, bob) = ideal_f2p(IdealCOT::default());
    (IdealCOTSender(alice), IdealCOTReceiver(bob))
}

/// Ideal COT sender.
#[derive(Debug, Clone, Default)]
pub struct IdealCOTSender(Alice<IdealCOT>);

impl IdealCOTSender {
    /// Returns Alice.
    pub fn alice(&mut self) -> &mut Alice<IdealCOT> {
        &mut self.0
    }
}

#[async_trait]
impl<Ctx> OTSetup<Ctx> for IdealCOTSender
where
    Ctx: Context,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

impl Allocate for IdealCOTSender {
    fn alloc(&mut self, _count: usize) {}
}

#[async_trait]
impl<Ctx> Preprocess<Ctx> for IdealCOTSender
where
    Ctx: Context,
{
    type Error = OTError;

    async fn preprocess(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

impl Correlation for IdealCOTSender {
    type Correlation = Block;

    fn delta(&self) -> Block {
        self.0.lock().delta()
    }
}

#[async_trait]
impl<Ctx: Context> COTSender<Ctx, Block> for IdealCOTSender {
    async fn send_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<COTSenderOutput<Block>, OTError> {
        Ok(self.0.call(ctx, count, cot).await)
    }
}

#[async_trait]
impl<Ctx: Context> RandomCOTSender<Ctx, Block> for IdealCOTSender {
    async fn send_random_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTSenderOutput<Block>, OTError> {
        Ok(self.0.call(ctx, count, rcot).await)
    }
}

/// Ideal COT receiver.
#[derive(Debug, Clone, Default)]
pub struct IdealCOTReceiver(Bob<IdealCOT>);

#[async_trait]
impl<Ctx> OTSetup<Ctx> for IdealCOTReceiver
where
    Ctx: Context,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

impl Allocate for IdealCOTReceiver {
    fn alloc(&mut self, _count: usize) {}
}

#[async_trait]
impl<Ctx> Preprocess<Ctx> for IdealCOTReceiver
where
    Ctx: Context,
{
    type Error = OTError;

    async fn preprocess(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> COTReceiver<Ctx, bool, Block> for IdealCOTReceiver {
    async fn receive_correlated(
        &mut self,
        ctx: &mut Ctx,
        choices: &[bool],
    ) -> Result<COTReceiverOutput<Block>, OTError> {
        Ok(self.0.call(ctx, choices.to_vec(), cot).await)
    }
}

#[async_trait]
impl<Ctx: Context> RandomCOTReceiver<Ctx, bool, Block> for IdealCOTReceiver {
    async fn receive_random_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, OTError> {
        Ok(self.0.call(ctx, count, rcot).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_common::executor::test_st_executor;
    use mpz_ot_core::test::assert_cot;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[tokio::test]
    async fn test_ideal_cot() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut alice, mut bob) = ideal_cot();

        let delta = alice.delta();

        let count = 10;
        let choices = (0..count).map(|_| rng.gen()).collect::<Vec<bool>>();

        let (
            COTSenderOutput {
                id: id_a,
                msgs: sender_msgs,
            },
            COTReceiverOutput {
                id: id_b,
                msgs: receiver_msgs,
            },
        ) = tokio::try_join!(
            alice.send_correlated(&mut ctx_a, count),
            bob.receive_correlated(&mut ctx_b, &choices)
        )
        .unwrap();

        assert_eq!(id_a, id_b);
        assert_eq!(count, sender_msgs.len());
        assert_eq!(count, receiver_msgs.len());
        assert_cot(delta, &choices, &sender_msgs, &receiver_msgs);
    }

    #[tokio::test]
    async fn test_ideal_rcot() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut alice, mut bob) = ideal_rcot();

        let delta = alice.delta();

        let count = 10;

        let (
            RCOTSenderOutput {
                id: id_a,
                msgs: sender_msgs,
            },
            RCOTReceiverOutput {
                id: id_b,
                choices,
                msgs: receiver_msgs,
            },
        ) = tokio::try_join!(
            alice.send_random_correlated(&mut ctx_a, count),
            bob.receive_random_correlated(&mut ctx_b, count)
        )
        .unwrap();

        assert_eq!(id_a, id_b);
        assert_eq!(count, sender_msgs.len());
        assert_eq!(count, receiver_msgs.len());
        assert_eq!(count, choices.len());
        assert_cot(delta, &choices, &sender_msgs, &receiver_msgs);
    }
}
