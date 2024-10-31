//! Chosen-message oblivious transfer.

use mpz_common::future::Output;

use crate::TransferId;

/// Output the sender receives from the OT functionality.
#[derive(Debug)]
pub struct OTSenderOutput {
    /// Transfer id.
    pub id: TransferId,
}

/// Oblivious transfer sender.
pub trait OTSender<T> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<Ok = OTSenderOutput>;

    /// Allocates `count` OTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Queues sending of OTs.
    ///
    /// # Arguments
    ///
    /// * `msgs` - Messages to send.
    fn queue_send_ot(&mut self, msgs: &[[T; 2]]) -> Result<Self::Future, Self::Error>;
}

/// Output the receiver receives from the OT functionality.
#[derive(Debug)]
pub struct OTReceiverOutput<T> {
    /// Transfer id.
    pub id: TransferId,
    /// Chosen messages.
    pub msgs: Vec<T>,
}

/// Oblivious transfer receiver.
pub trait OTReceiver<T, U> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<Ok = OTReceiverOutput<U>>;

    /// Allocates `count` OTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Queues receiving of OTs.
    ///
    /// # Arguments
    ///
    /// * `choices` - OT choices.
    fn queue_recv_ot(&mut self, choices: &[T]) -> Result<Self::Future, Self::Error>;
}
