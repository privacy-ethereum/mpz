//! Ideal functionality for correlated oblivious transfer.

use std::marker::PhantomData;

use async_trait::async_trait;

use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Context,
};
use mpz_ot_core::ideal::ot::IdealOT;

use crate::{
    CommittedOTReceiver, OTError, OTReceiver, OTReceiverOutput, OTSender, OTSenderOutput, OTSetup,
    VerifiableOTSender,
};

fn ot<T: Copy + Send + Sync + 'static>(
    f: &mut IdealOT,
    sender_msgs: Vec<[T; 2]>,
    receiver_choices: Vec<bool>,
) -> (OTSenderOutput, OTReceiverOutput<T>) {
    assert_eq!(sender_msgs.len(), receiver_choices.len());

    f.chosen(receiver_choices, sender_msgs)
}

fn verify(f: &mut IdealOT, _: (), _: ()) -> (Vec<bool>, ()) {
    (f.choices().to_vec(), ())
}

/// Returns an ideal OT sender and receiver.
pub fn ideal_ot<T: Send + 'static, U: Send + 'static>() -> (IdealOTSender<T>, IdealOTReceiver<U>) {
    let (alice, bob) = ideal_f2p(IdealOT::default());
    (
        IdealOTSender(alice, PhantomData),
        IdealOTReceiver(bob, PhantomData),
    )
}

/// Ideal OT sender.
#[derive(Debug, Clone)]
pub struct IdealOTSender<T>(Alice<IdealOT>, PhantomData<fn() -> T>);

#[async_trait]
impl<Ctx, T> OTSetup<Ctx> for IdealOTSender<T>
where
    Ctx: Context,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context, T: Copy + Send + Sync + 'static> OTSender<Ctx, [T; 2]>
    for IdealOTSender<[T; 2]>
{
    async fn send(&mut self, ctx: &mut Ctx, msgs: &[[T; 2]]) -> Result<OTSenderOutput, OTError> {
        Ok(self.0.call(ctx, msgs.to_vec(), ot).await)
    }
}

#[async_trait]
impl<Ctx: Context, T: Copy + Send + Sync + 'static> VerifiableOTSender<Ctx, bool, [T; 2]>
    for IdealOTSender<[T; 2]>
{
    async fn verify_choices(&mut self, ctx: &mut Ctx) -> Result<Vec<bool>, OTError> {
        Ok(self.0.call(ctx, (), verify).await)
    }
}

/// Ideal OT receiver.
#[derive(Debug, Clone)]
pub struct IdealOTReceiver<T>(Bob<IdealOT>, PhantomData<fn() -> T>);

#[async_trait]
impl<Ctx, T> OTSetup<Ctx> for IdealOTReceiver<T>
where
    Ctx: Context,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context, T: Copy + Send + Sync + 'static> OTReceiver<Ctx, bool, T>
    for IdealOTReceiver<T>
{
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choices: &[bool],
    ) -> Result<OTReceiverOutput<T>, OTError> {
        Ok(self.0.call(ctx, choices.to_vec(), ot).await)
    }
}

#[async_trait]
impl<Ctx: Context, T: Copy + Send + Sync + 'static> CommittedOTReceiver<Ctx, bool, T>
    for IdealOTReceiver<T>
{
    async fn reveal_choices(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(self.0.call(ctx, (), verify).await)
    }
}
