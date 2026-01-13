//! Circuit types for Three-Halves garbling scheme

use serde::{Deserialize, Serialize};

use crate::DEFAULT_BATCH_SIZE;

use super::{ControlBits, ThreeHalvesGate};

/// A garbled circuit using the Three-Halves scheme.
#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    /// Encrypted gates.
    pub gates: Vec<EncryptedGate>,
}

/// Encrypted gate for Three Halves scheme.
///
/// Contains both the gate ciphertexts (1.5κ bits) and control bits (1 byte)
/// needed for evaluation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedGate {
    /// Gate ciphertexts (1.5κ bits = 24 bytes)
    pub gate: ThreeHalvesGate,
    /// Control bits for evaluator (1 byte)
    pub control_bits: ControlBits,
}

impl EncryptedGate {
    /// Create a new encrypted gate.
    pub fn new(gate: ThreeHalvesGate, control_bits: ControlBits) -> Self {
        Self { gate, control_bits }
    }
}

/// A batch of encrypted gates.
///
/// # Parameters
///
/// - `N`: The size of a batch.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedGateBatch<const N: usize = DEFAULT_BATCH_SIZE>(
    #[serde(with = "serde_arrays")] [EncryptedGate; N],
);

impl<const N: usize> EncryptedGateBatch<N> {
    /// Creates a new batch of encrypted gates.
    pub fn new(batch: [EncryptedGate; N]) -> Self {
        Self(batch)
    }

    /// Returns the inner array.
    pub fn into_array(self) -> [EncryptedGate; N] {
        self.0
    }
}
