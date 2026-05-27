//! Random vector oblivious linear evaluation.

use mpz_common::future::Output;
use mpz_fields::{ExtensionField, Field};

use crate::VoleId;

/// Output the sender receives from the random VOLE functionality.
#[derive(Debug, Clone)]
pub struct RVOLESenderOutput<E: Field> {
    /// VOLE id.
    pub id: VoleId,
    /// Random keys.
    pub keys: Vec<E>,
}

/// Random VOLE sender.
pub trait RVOLESender<E: Field> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<RVOLESenderOutput<E>>;

    /// Allocates `count` RVOLEs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available RVOLEs.
    fn available(&self) -> usize;

    /// Returns the global correlation key, `delta`.
    fn delta(&self) -> E;

    /// Returns preprocessed RVOLEs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed RVOLEs to try to consume.
    fn try_send_vole(&mut self, count: usize) -> Result<RVOLESenderOutput<E>, Self::Error>;

    /// Queues `count` RVOLEs for sending.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RVOLEs to queue for sending.
    fn queue_send_vole(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}

/// Output the receiver receives from the random VOLE functionality.
#[derive(Debug, Clone)]
pub struct RVOLEReceiverOutput<W, E: Field> {
    /// VOLE id.
    pub id: VoleId,
    /// Random values in the subfield `W ⊆ E`.
    pub values: Vec<W>,
    /// MACs.
    pub macs: Vec<E>,
}

/// Random VOLE receiver.
///
/// The receiver is parameterized over base field `W` and extension
/// `E: ExtensionField<W>`; its values live in `W`, its MACs in `E`,
/// and the correlation is `mac = key + delta · E::embed(value)`.
/// Full-field VOLE is the special case `W = E`.
pub trait RVOLEReceiver<W: Field, E: ExtensionField<W>> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<RVOLEReceiverOutput<W, E>>;

    /// Allocates `count` RVOLEs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available RVOLEs.
    fn available(&self) -> usize;

    /// Returns preprocessed RVOLEs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed RVOLEs to try to consume.
    fn try_recv_vole(
        &mut self,
        count: usize,
    ) -> Result<RVOLEReceiverOutput<W, E>, Self::Error>;

    /// Queues `count` RVOLEs for receiving.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RVOLEs to queue for receiving.
    fn queue_recv_vole(&mut self, count: usize) -> Result<Self::Future, Self::Error>;
}
