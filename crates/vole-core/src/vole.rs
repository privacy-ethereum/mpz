//! Vector oblivious linear evaluation.

mod derandomize;

pub use derandomize::{
    DerandVOLEReceiver, DerandVOLEReceiverError, DerandVOLESender, DerandVOLESenderError,
    VoleAdjustment,
};

use mpz_common::future::Output;
use mpz_fields::{ExtensionField, Field};

use crate::VoleId;

/// Output the sender receives from the VOLE functionality.
#[derive(Debug, Clone)]
pub struct VOLESenderOutput {
    /// VOLE id.
    pub id: VoleId,
}

/// VOLE sender.
pub trait VOLESender<E: Field> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<VOLESenderOutput>;

    /// Allocates `count` VOLEs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available VOLEs.
    fn available(&self) -> usize;

    /// Returns the global correlation key, `delta`.
    fn delta(&self) -> E;

    /// Queues sending of VOLEs.
    ///
    /// # Arguments
    ///
    /// * `keys` - Keys to send.
    fn queue_send_vole(&mut self, keys: &[E]) -> Result<Self::Future, Self::Error>;
}

/// Output the receiver receives from the VOLE functionality.
#[derive(Debug, Clone)]
pub struct VOLEReceiverOutput<E: Field> {
    /// VOLE id.
    pub id: VoleId,
    /// MACs.
    pub macs: Vec<E>,
}

/// VOLE receiver.
///
/// The receiver is parameterized over base field `W` and extension
/// `E: ExtensionField<W>`; its values live in `W`, its MACs in `E`,
/// and the correlation is `mac = key + delta · E::embed(value)`.
/// Full-field VOLE is the special case `W = E`.
pub trait VOLEReceiver<W: Field, E: ExtensionField<W>> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Future type.
    type Future: Output<VOLEReceiverOutput<E>>;

    /// Allocates `count` VOLEs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available VOLEs.
    fn available(&self) -> usize;

    /// Queues receiving of VOLEs.
    ///
    /// # Arguments
    ///
    /// * `values` - VOLE target values.
    fn queue_recv_vole(&mut self, values: &[W]) -> Result<Self::Future, Self::Error>;
}
