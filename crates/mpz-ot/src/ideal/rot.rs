//! Ideal functionality for random oblivious transfer.

use async_trait::async_trait;

use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Context,
};
use mpz_core::Block;
use mpz_ot_core::{ideal::rot::IdealROT, ROTReceiverOutput, ROTSenderOutput};

use crate::{OTError, OTSetup, RandomOTReceiver, RandomOTSender};

fn rot<const N: usize>(
    f: &mut IdealROT,
    sender_count: usize,
    receiver_count: usize,
) -> (
    ROTSenderOutput<[[u8; N]; 2]>,
    ROTReceiverOutput<bool, [u8; N]>,
) {
    assert_eq!(sender_count, receiver_count);

    f.random(sender_count)
}

/// Returns an ideal ROT sender and receiver.
pub fn ideal_rot() -> (IdealROTSender, IdealROTReceiver) {
    let (alice, bob) = ideal_f2p(IdealROT::default());
    (IdealROTSender(alice), IdealROTReceiver(bob))
}

/// Ideal ROT sender.
#[derive(Debug, Clone)]
pub struct IdealROTSender(Alice<IdealROT>);

#[async_trait]
impl<Ctx> OTSetup<Ctx> for IdealROTSender
where
    Ctx: Context,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> RandomOTSender<Ctx, [Block; 2]> for IdealROTSender {
    async fn send_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTSenderOutput<[Block; 2]>, OTError> {
        let output = RandomOTSender::<Ctx, [[u8; 16]; 2]>::send_random(self, ctx, count).await?;

        let block_msgs = output
            .msgs
            .iter()
            .map(|&value| [Block::new(value[0]), Block::new(value[1])])
            .collect();
        let block_output = ROTSenderOutput {
            id: output.id,
            msgs: block_msgs,
        };

        Ok(block_output)
    }
}

#[async_trait]
impl<const N: usize, Ctx: Context> RandomOTSender<Ctx, [[u8; N]; 2]> for IdealROTSender {
    async fn send_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTSenderOutput<[[u8; N]; 2]>, OTError> {
        Ok(self.0.call(ctx, count, rot).await)
    }
}

/// Ideal ROT receiver.
#[derive(Debug, Clone)]
pub struct IdealROTReceiver(Bob<IdealROT>);

#[async_trait]
impl<Ctx> OTSetup<Ctx> for IdealROTReceiver
where
    Ctx: Context,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> RandomOTReceiver<Ctx, bool, Block> for IdealROTReceiver {
    async fn receive_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, OTError> {
        let output =
            RandomOTReceiver::<Ctx, bool, [u8; 16]>::receive_random(self, ctx, count).await?;

        let block_msgs = output.msgs.iter().map(|&value| Block::new(value)).collect();
        let block_output = ROTReceiverOutput {
            id: output.id,
            choices: output.choices,
            msgs: block_msgs,
        };

        Ok(block_output)
    }
}

#[async_trait]
impl<const N: usize, Ctx: Context> RandomOTReceiver<Ctx, bool, [u8; N]> for IdealROTReceiver {
    async fn receive_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, [u8; N]>, OTError> {
        Ok(self.0.call(ctx, count, rot).await)
    }
}
