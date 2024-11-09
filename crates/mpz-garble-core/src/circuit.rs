use std::ops::Index;

use mpz_core::Block;
use serde::{Deserialize, Serialize};

use crate::DEFAULT_BATCH_SIZE;

/// A garbled circuit.
#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    /// Encrypted gates.
    pub gates: Vec<EncryptedGate>,
}

/// Encrypted gate truth table
///
/// For the half-gate garbling scheme a truth table will typically have 2 rows,
/// except for in privacy-free garbling mode where it will be reduced to 1.
///
/// We do not yet support privacy-free garbling.
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EncryptedGate(#[serde(with = "serde_arrays")] pub(crate) [Block; 2]);

impl EncryptedGate {
    pub(crate) fn new(inner: [Block; 2]) -> Self {
        Self(inner)
    }
}

impl Index<usize> for EncryptedGate {
    type Output = Block;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
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
