//! Random vector oblivious polynomial evaluation.

use mpz_common::future::Output;
use mpz_fields::Field;

use crate::VoleId;

/// Output the sender receives from the random VOPE functionality.
#[derive(Debug, Clone)]
pub struct RVOPESenderOutput<E: Field> {
    /// VOPE id.
    pub id: VoleId,
    /// Polynomial evaluations at `delta`.
    pub evaluations: Vec<E>,
}

/// Random VOPE sender.
pub trait RVOPESender<E: Field> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<RVOPESenderOutput<E>>;

    /// Allocates `count` RVOPEs of the given `degree` for preprocessing.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RVOPEs to allocate.
    /// * `degree` - Number of coefficients per polynomial.
    fn alloc(&mut self, count: usize, degree: usize) -> Result<(), Self::Error>;

    /// Returns the number of available RVOPEs.
    fn available(&self) -> usize;

    /// Returns preprocessed RVOPEs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed RVOPEs to try to consume.
    fn try_send_vope(&mut self, count: usize) -> Result<RVOPESenderOutput<E>, Self::Error>;

    /// Queues `count` RVOPEs for sending.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RVOPEs to queue for sending.
    fn queue_send_vope(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}

/// Output the receiver receives from the random VOPE functionality.
#[derive(Debug, Clone)]
pub struct RVOPEReceiverOutput<E: Field> {
    /// VOPE id.
    pub id: VoleId,
    /// Random polynomial coefficients.
    pub polynomials: Vec<Vec<E>>,
}

/// Random VOPE receiver.
pub trait RVOPEReceiver<E: Field> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<RVOPEReceiverOutput<E>>;

    /// Allocates `count` RVOPEs of the given `degree` for preprocessing.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RVOPEs to allocate.
    /// * `degree` - Number of coefficients per polynomial.
    fn alloc(&mut self, count: usize, degree: usize) -> Result<(), Self::Error>;

    /// Returns the number of available RVOPEs.
    fn available(&self) -> usize;

    /// Returns preprocessed RVOPEs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed RVOPEs to try to consume.
    fn try_recv_vope(&mut self, count: usize) -> Result<RVOPEReceiverOutput<E>, Self::Error>;

    /// Queues `count` RVOPEs for receiving.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RVOPEs to queue for receiving.
    fn queue_recv_vope(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}
