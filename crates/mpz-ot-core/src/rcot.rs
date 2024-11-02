//! Random correlated oblivious transfer.

use mpz_common::future::Output;

use crate::TransferId;

/// Output the sender receives from the random COT functionality.
#[derive(Debug)]
pub struct RCOTSenderOutput<T> {
    /// Transfer id.
    pub id: TransferId,
    /// Random keys.
    pub keys: Vec<T>,
}

/// Random correlated oblivious transfer sender.
pub trait RCOTSender<T> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<RCOTSenderOutput<T>>;

    /// Allocates `count` RCOTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available RCOTs.
    fn available(&self) -> usize;

    /// Returns the global correlation key, `delta`.
    fn delta(&self) -> T;

    /// Returns preprocessed RCOTs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed RCOTs to try to consume.
    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<T>, Self::Error>;

    /// Queues `count` RCOTs for sending.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RCOTs to queue for sending.
    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}

/// Output the receiver receives from the random COT functionality.
#[derive(Debug)]
pub struct RCOTReceiverOutput<T, U> {
    /// Transfer id.
    pub id: TransferId,
    /// Choice bits.
    pub choices: Vec<T>,
    /// Chosen messages.
    pub msgs: Vec<U>,
}

/// Random correlated oblivious transfer receiver.
pub trait RCOTReceiver<T, U> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<RCOTReceiverOutput<T, U>>;

    /// Allocates `count` RCOTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available RCOTs.
    fn available(&self) -> usize;

    /// Returns preprocessed RCOTs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed RCOTs to try to consume.
    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<T, U>, Self::Error>;

    /// Queues `count` RCOTs for receiving.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RCOTs to queue for receiving.
    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}
