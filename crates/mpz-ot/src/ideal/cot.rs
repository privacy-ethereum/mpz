//! Ideal functionality for correlated oblivious transfer.

use async_trait::async_trait;

use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Context,
};
use mpz_core::Block;
use mpz_ot_core::{
    ideal::cot::IdealCOT, COTReceiverOutput, COTSenderOutput, RCOTReceiverOutput, RCOTSenderOutput,
};

use crate::{COTReceiver, COTSender, OTError, OTSetup, RandomCOTReceiver};

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

/// Ideal OT sender.
#[derive(Debug, Clone)]
pub struct IdealCOTSender(Alice<IdealCOT>);

#[async_trait]
impl<Ctx> OTSetup<Ctx> for IdealCOTSender
where
    Ctx: Context,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
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

/// Ideal OT receiver.
#[derive(Debug, Clone)]
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
