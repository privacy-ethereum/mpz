//! Random oblivious transfer.

mod any;
mod randomize;

pub use any::{AnyReceiver, AnySender};
pub use randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender};

use mpz_common::future::Output;

use crate::TransferId;

/// Output the sender receives from the ROT functionality.
#[derive(Debug)]
pub struct ROTSenderOutput<T> {
    /// Transfer id.
    pub id: TransferId,
    /// Random keys.
    pub keys: Vec<T>,
}

/// Random oblivious transfer sender.
pub trait ROTSender<T> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<ROTSenderOutput<T>>;

    /// Allocates `count` ROTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available ROTs.
    fn available(&self) -> usize;

    /// Returns preprocessed ROTs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed ROTs to try to consume.
    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<T>, Self::Error>;

    /// Queues sending of ROTs.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of ROTs to send.
    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}

/// Output the receiver receives from the ROT functionality.
#[derive(Debug)]
pub struct ROTReceiverOutput<T, U> {
    /// Transfer id.
    pub id: TransferId,
    /// Random choices.
    pub choices: Vec<T>,
    /// Chosen msgs.
    pub msgs: Vec<U>,
}

/// Random oblivious transfer receiver.
pub trait ROTReceiver<T, U> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<ROTReceiverOutput<T, U>>;

    /// Allocates `count` ROTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available ROTs.
    fn available(&self) -> usize;

    /// Returns preprocessed ROTs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed ROTs to try to consume.
    fn try_recv_rot(&mut self, count: usize) -> Result<ROTReceiverOutput<T, U>, Self::Error>;

    /// Queues receiving of ROTs.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of ROTs to receive.
    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}
