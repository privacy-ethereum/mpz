use mpz_common::future::Output;

use crate::{OLEId, OLEShare};

/// Sender's output of the ROLE functionality.
#[derive(Debug)]
pub struct ROLESenderOutput<F> {
    /// OLE identifier.
    pub id: OLEId,
    /// Shares of the ROLE.
    pub shares: Vec<OLEShare<F>>,
}

/// Random OLE sender.
pub trait ROLESender<F> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<ROLESenderOutput<F>>;

    /// Allocates `count` ROLE for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of preprocessed ROLE available.
    fn available(&self) -> usize;

    /// Returns `count` ROLE, if available.
    fn try_send_role(&mut self, count: usize) -> Result<ROLESenderOutput<F>, Self::Error>;

    /// Queues `count` ROLE.
    fn queue_send_role(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}

/// Receiver's output of the ROLE functionality.
#[derive(Debug)]
pub struct ROLEReceiverOutput<F> {
    /// OLE identifier.
    pub id: OLEId,
    /// Shares of the ROLE.
    pub shares: Vec<OLEShare<F>>,
}

/// Random OLE receiver.
pub trait ROLEReceiver<F> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<ROLEReceiverOutput<F>>;

    /// Allocates `count` ROLE for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of preprocessed ROLE available.
    fn available(&self) -> usize;

    /// Returns `count` ROLE, if available.
    fn try_recv_role(&mut self, count: usize) -> Result<ROLEReceiverOutput<F>, Self::Error>;

    /// Queues `count` ROLE.
    fn queue_recv_role(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}
