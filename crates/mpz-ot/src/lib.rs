//! Implementations of oblivious transfer protocols.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

pub mod chou_orlandi;
#[cfg(any(test, feature = "ideal"))]
pub mod ideal;
pub mod kos;

use async_trait::async_trait;

pub use mpz_ot_core::{
    COTReceiverOutput, COTSenderOutput, OTReceiverOutput, OTSenderOutput, RCOTReceiverOutput,
    RCOTSenderOutput, ROTReceiverOutput, ROTSenderOutput, TransferId,
};

/// An oblivious transfer error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OTError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("context error: {0}")]
    Context(#[from] mpz_common::ContextError),
    #[error("mutex error: {0}")]
    Mutex(#[from] mpz_common::sync::MutexError),
    #[error("sender error: {0}")]
    SenderError(Box<dyn std::error::Error + Send + Sync>),
    #[error("receiver error: {0}")]
    ReceiverError(Box<dyn std::error::Error + Send + Sync>),
}

/// An oblivious transfer protocol that needs to perform a one-time setup.
#[async_trait]
pub trait OTSetup<Ctx> {
    /// Runs any one-time setup for the protocol.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError>;
}

/// An oblivious transfer sender.
#[async_trait]
pub trait OTSender<Ctx, T> {
    /// Obliviously transfers the messages to the receiver.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `msgs` - The messages to obliviously transfer.
    async fn send(&mut self, ctx: &mut Ctx, msgs: &[T]) -> Result<OTSenderOutput, OTError>;
}

/// A correlated oblivious transfer sender.
#[async_trait]
pub trait COTSender<Ctx, T> {
    /// Obliviously transfers the correlated messages to the receiver.
    ///
    /// Returns the `0`-bit messages that were obliviously transferred.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of correlated messages to obliviously transfer.
    async fn send_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<COTSenderOutput<T>, OTError>;
}

/// A random OT sender.
#[async_trait]
pub trait RandomOTSender<Ctx, T> {
    /// Outputs pairs of random messages.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of pairs of random messages to output.
    async fn send_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTSenderOutput<T>, OTError>;
}

/// A random correlated oblivious transfer sender.
#[async_trait]
pub trait RandomCOTSender<Ctx, T> {
    /// Obliviously transfers the correlated messages to the receiver.
    ///
    /// Returns the `0`-bit messages that were obliviously transferred.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of correlated messages to obliviously transfer.
    async fn send_random_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTSenderOutput<T>, OTError>;
}

/// An oblivious transfer receiver.
#[async_trait]
pub trait OTReceiver<Ctx, T, U> {
    /// Obliviously receives data from the sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `choices` - The choices made by the receiver.
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choices: &[T],
    ) -> Result<OTReceiverOutput<U>, OTError>;
}

/// A correlated oblivious transfer receiver.
#[async_trait]
pub trait COTReceiver<Ctx, T, U> {
    /// Obliviously receives correlated messages from the sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `choices` - The choices made by the receiver.
    async fn receive_correlated(
        &mut self,
        ctx: &mut Ctx,
        choices: &[T],
    ) -> Result<COTReceiverOutput<U>, OTError>;
}

/// A random OT receiver.
#[async_trait]
pub trait RandomOTReceiver<Ctx, T, U> {
    /// Outputs the choice bits and the corresponding messages.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of random messages to receive.
    async fn receive_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTReceiverOutput<T, U>, OTError>;
}

/// A random correlated oblivious transfer receiver.
#[async_trait]
pub trait RandomCOTReceiver<Ctx, T, U> {
    /// Obliviously receives correlated messages with random choices.
    ///
    /// Returns a tuple of the choices and the messages, respectively.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of correlated messages to obliviously receive.
    async fn receive_random_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTReceiverOutput<T, U>, OTError>;
}

/// An oblivious transfer sender that is committed to its messages and can reveal them
/// to the receiver to verify them.
#[async_trait]
pub trait CommittedOTSender<Ctx, T>: OTSender<Ctx, T> {
    /// Reveals all messages sent to the receiver.
    ///
    /// # Warning
    ///
    /// Obviously, you should be sure you want to do this before calling this function!
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    async fn reveal(&mut self, ctx: &mut Ctx) -> Result<(), OTError>;
}

/// An oblivious transfer sender that can verify the receiver's choices.
#[async_trait]
pub trait VerifiableOTSender<Ctx, T, U>: OTSender<Ctx, U> {
    /// Receives the purported choices made by the receiver and verifies them.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    async fn verify_choices(&mut self, ctx: &mut Ctx) -> Result<Vec<T>, OTError>;
}

/// An oblivious transfer receiver that is committed to its choices and can reveal them
/// to the sender to verify them.
#[async_trait]
pub trait CommittedOTReceiver<Ctx, T, U>: OTReceiver<Ctx, T, U> {
    /// Reveals the choices made by the receiver.
    ///
    /// # Warning
    ///
    /// Obviously, you should be sure you want to do this before calling this function!
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    async fn reveal_choices(&mut self, ctx: &mut Ctx) -> Result<(), OTError>;
}

/// An oblivious transfer receiver that can verify the sender's messages.
#[async_trait]
pub trait VerifiableOTReceiver<Ctx, T, U, V>: OTReceiver<Ctx, T, U> {
    /// Accepts revealed secrets from the sender which are requried to verify previous messages.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    async fn accept_reveal(&mut self, ctx: &mut Ctx) -> Result<(), OTError>;

    /// Verifies purported messages sent by the sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `id` - The transfer id of the messages to verify.
    /// * `msgs` - The purported messages sent by the sender.
    async fn verify(&mut self, ctx: &mut Ctx, id: TransferId, msgs: &[V]) -> Result<(), OTError>;
}
