//! Correlated oblivious transfer.

mod derandomize;

pub use derandomize::{
    Adjust, DerandCOTReceiver, DerandCOTReceiverError, DerandCOTSender, DerandCOTSenderError,
};

use mpz_common::future::Output;

use crate::TransferId;

/// Output the sender receives from the COT functionality.
#[derive(Debug)]
pub struct COTSenderOutput {
    /// Transfer id.
    pub id: TransferId,
}

/// Correlated oblivious transfer sender.
pub trait COTSender<T> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<COTSenderOutput>;

    /// Allocates `count` COTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available COTs.
    fn available(&self) -> usize;

    /// Returns the global correlation key, `delta`.
    fn delta(&self) -> T;

    /// Queues sending of COTs.
    ///
    /// # Arguments
    ///
    /// * `keys` - Keys corresponding to the choice bit value 0 to send.
    fn queue_send_cot(&mut self, keys: &[T]) -> Result<Self::Future, Self::Error>;
}

/// Output the receiver receives from the COT functionality.
#[derive(Debug)]
pub struct COTReceiverOutput<T> {
    /// Transfer id.
    pub id: TransferId,
    /// Chosen messages.
    pub msgs: Vec<T>,
}

/// Correlated oblivious transfer receiver.
pub trait COTReceiver<T, U> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<COTReceiverOutput<U>>;

    /// Allocates `count` COTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available COTs.
    fn available(&self) -> usize;

    /// Queues receiving of COTs.
    ///
    /// # Arguments
    ///
    /// * `choices` - COT choices.
    fn queue_recv_cot(&mut self, choices: &[T]) -> Result<Self::Future, Self::Error>;
}
