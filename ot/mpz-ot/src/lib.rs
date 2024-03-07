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
#[cfg(feature = "ideal")]
pub mod ideal;
pub mod kos;

use async_trait::async_trait;
use mpz_common::Context;

/// An oblivious transfer error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OTError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("mutex error: {0}")]
    Mutex(#[from] mpz_common::sync::MutexError),
    #[error("sender error: {0}")]
    SenderError(Box<dyn std::error::Error + Send + Sync>),
    #[error("receiver error: {0}")]
    ReceiverError(Box<dyn std::error::Error + Send + Sync>),
}

/// An oblivious transfer protocol that needs to perform a one-time setup.
#[async_trait]
pub trait OTSetup<Ctx>
where
    Ctx: Context,
{
    /// Runs any one-time setup for the protocol.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError>;
}

/// An oblivious transfer sender.
#[async_trait]
pub trait OTSender<Ctx, T>
where
    Ctx: Context,
    T: Send + Sync,
{
    /// Obliviously transfers the messages to the receiver.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `msgs` - The messages to obliviously transfer.
    async fn send(&mut self, ctx: &mut Ctx, msgs: &[T]) -> Result<(), OTError>;
}

/// A correlated oblivious transfer sender.
#[async_trait]
pub trait COTSender<Ctx, T>
where
    Ctx: Context,
    T: Send + Sync,
{
    /// Obliviously transfers the correlated messages to the receiver.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `msgs` - The `0`-bit messages to use during the oblivious transfer.
    async fn send_correlated(&mut self, ctx: &mut Ctx, msgs: &[T]) -> Result<(), OTError>;
}

/// A random OT sender.
#[async_trait]
pub trait RandomOTSender<Ctx, T>
where
    Ctx: Context,
    T: Send + Sync,
{
    /// Outputs pairs of random messages.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of pairs of random messages to output.
    async fn send_random(&mut self, ctx: &mut Ctx, count: usize) -> Result<Vec<T>, OTError>;
}

/// A random correlated oblivious transfer sender.
#[async_trait]
pub trait RandomCOTSender<Ctx, T>
where
    Ctx: Context,
    T: Send + Sync,
{
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
    ) -> Result<Vec<T>, OTError>;
}

/// An oblivious transfer receiver.
#[async_trait]
pub trait OTReceiver<Ctx, T, U>
where
    Ctx: Context,
    T: Send + Sync,
    U: Send + Sync,
{
    /// Obliviously receives data from the sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `choices` - The choices made by the receiver.
    async fn receive(&mut self, ctx: &mut Ctx, choices: &[T]) -> Result<Vec<U>, OTError>;
}

/// A correlated oblivious transfer receiver.
#[async_trait]
pub trait COTReceiver<Ctx, T, U>
where
    Ctx: Context,
    T: Send + Sync,
    U: Send + Sync,
{
    /// Obliviously receives correlated messages from the sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `choices` - The choices made by the receiver.
    async fn receive_correlated(&mut self, ctx: &mut Ctx, choices: &[T])
        -> Result<Vec<U>, OTError>;
}

/// A random OT receiver.
#[async_trait]
pub trait RandomOTReceiver<Ctx, T, U>
where
    Ctx: Context,
    T: Send + Sync,
    U: Send + Sync,
{
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
    ) -> Result<(Vec<T>, Vec<U>), OTError>;
}

/// A random correlated oblivious transfer receiver.
#[async_trait]
pub trait RandomCOTReceiver<Ctx, T, U>
where
    Ctx: Context,
    T: Send + Sync,
    U: Send + Sync,
{
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
    ) -> Result<(Vec<T>, Vec<U>), OTError>;
}

/// An oblivious transfer sender that is committed to its messages and can reveal them
/// to the receiver to verify them.
#[async_trait]
pub trait CommittedOTSender<Ctx, T>: OTSender<Ctx, T>
where
    Ctx: Context,
    T: Send + Sync,
{
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
pub trait VerifiableOTSender<Ctx, T, U>: OTSender<Ctx, U>
where
    Ctx: Context,
    U: Send + Sync,
{
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
pub trait CommittedOTReceiver<Ctx, T, U>: OTReceiver<Ctx, T, U>
where
    Ctx: Context,
    T: Send + Sync,
    U: Send + Sync,
{
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
pub trait VerifiableOTReceiver<Ctx, T, U, V>: OTReceiver<Ctx, T, U>
where
    Ctx: Context,
    T: Send + Sync,
    U: Send + Sync,
    V: Send + Sync,
{
    /// Verifies purported messages sent by the sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `id` - The transfer id of the messages to verify.
    /// * `msgs` - The purported messages sent by the sender.
    async fn verify(&mut self, ctx: &mut Ctx, id: usize, msgs: &[V]) -> Result<(), OTError>;
}
