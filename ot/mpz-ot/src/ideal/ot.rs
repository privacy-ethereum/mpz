//! Ideal functionality for oblivious transfer.

use crate::{
    CommittedOTReceiver, CommittedOTSender, OTError, OTReceiver, OTSender, OTSetup,
    VerifiableOTReceiver, VerifiableOTSender,
};
use async_trait::async_trait;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use mpz_common::Context;

/// Ideal OT sender.
#[derive(Debug)]
pub struct IdealOTSender<T> {
    sender: mpsc::Sender<Vec<[T; 2]>>,
    msgs: Vec<[T; 2]>,
    choices_receiver: Option<oneshot::Receiver<Vec<bool>>>,
}

/// Ideal OT receiver.
#[derive(Debug)]
pub struct IdealOTReceiver<T> {
    receiver: mpsc::Receiver<Vec<[T; 2]>>,
    choices: Vec<bool>,
    choices_sender: Option<oneshot::Sender<Vec<bool>>>,
}

/// Creates a pair of ideal OT sender and receiver.
pub fn ideal_ot_pair<T: Send + Sync + 'static>() -> (IdealOTSender<T>, IdealOTReceiver<T>) {
    let (sender, receiver) = mpsc::channel(10);
    let (choices_sender, choices_receiver) = oneshot::channel();

    (
        IdealOTSender {
            sender,
            msgs: Vec::default(),
            choices_receiver: Some(choices_receiver),
        },
        IdealOTReceiver {
            receiver,
            choices: Vec::default(),
            choices_sender: Some(choices_sender),
        },
    )
}

#[async_trait]
impl<Ctx, T> OTSetup<Ctx> for IdealOTSender<T>
where
    Ctx: Context,
    T: Send + Sync,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx, T> OTSender<Ctx, [T; 2]> for IdealOTSender<T>
where
    Ctx: Context,
    T: Send + Sync + Clone + 'static,
{
    async fn send(&mut self, _ctx: &mut Ctx, msgs: &[[T; 2]]) -> Result<(), OTError> {
        self.msgs.extend(msgs.iter().cloned());

        self.sender
            .try_send(msgs.to_vec())
            .expect("DummySender should be able to send");

        Ok(())
    }
}

#[async_trait]
impl<Ctx, T> OTSetup<Ctx> for IdealOTReceiver<T>
where
    Ctx: Context,
    T: Send + Sync,
{
    async fn setup(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx, T> OTReceiver<Ctx, bool, T> for IdealOTReceiver<T>
where
    Ctx: Context,
    T: Send + Sync + 'static,
{
    async fn receive(&mut self, _ctx: &mut Ctx, choices: &[bool]) -> Result<Vec<T>, OTError> {
        self.choices.extend(choices.iter().copied());

        let payload = self
            .receiver
            .next()
            .await
            .expect("DummySender should send a value");

        Ok(payload
            .into_iter()
            .zip(choices)
            .map(|(v, c)| {
                let [low, high] = v;
                if *c {
                    high
                } else {
                    low
                }
            })
            .collect())
    }
}

#[async_trait]
impl<Ctx, U, V> VerifiableOTReceiver<Ctx, bool, U, V> for IdealOTReceiver<U>
where
    Ctx: Context,
    U: Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    async fn verify(&mut self, _ctx: &mut Ctx, _index: usize, _msgs: &[V]) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx, T> CommittedOTSender<Ctx, [T; 2]> for IdealOTSender<T>
where
    Ctx: Context,
    T: Send + Sync + Clone + 'static,
{
    async fn reveal(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx, T> CommittedOTReceiver<Ctx, bool, T> for IdealOTReceiver<T>
where
    Ctx: Context,
    T: Send + Sync + 'static,
{
    async fn reveal_choices(&mut self, _ctx: &mut Ctx) -> Result<(), OTError> {
        self.choices_sender
            .take()
            .expect("choices should not be revealed twice")
            .send(self.choices.clone())
            .expect("DummySender should be able to send");

        Ok(())
    }
}

#[async_trait]
impl<Ctx, T> VerifiableOTSender<Ctx, bool, [T; 2]> for IdealOTSender<T>
where
    Ctx: Context,
    T: Send + Sync + Clone + 'static,
{
    async fn verify_choices(&mut self, _ctx: &mut Ctx) -> Result<Vec<bool>, OTError> {
        Ok(self
            .choices_receiver
            .take()
            .expect("choices should not be verified twice")
            .await
            .expect("choices sender should not be dropped"))
    }
}

#[cfg(test)]
mod tests {
    use mpz_common::executor::test_st_executor;

    use super::*;

    // Test that the sender and receiver can be used to send and receive values
    #[tokio::test]
    async fn test_ideal_ot_owned() {
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);

        let values = vec![[0, 1], [2, 3]];
        let choices = vec![false, true];
        let (mut sender, mut receiver) = ideal_ot_pair::<u8>();

        sender.send(&mut ctx_sender, &values).await.unwrap();

        let received = receiver.receive(&mut ctx_receiver, &choices).await.unwrap();

        assert_eq!(received, vec![0, 3]);
    }
}
