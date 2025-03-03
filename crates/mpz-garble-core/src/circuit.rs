use std::ops::Index;

use mpz_core::{aes::FixedKeyAes, Block};
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

/// An authenticated half gate
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AuthHalfGate {
    #[serde(with = "serde_arrays")]
    pub(crate) gates: [Block; 2],
    pub(crate) mask: bool,
}

impl AuthHalfGate {
    /// Creates a new authenticated half gate
    pub fn new(gates: [Block; 2], mask: bool) -> Self {
        Self { gates, mask }
    }
}

/// Helper function for hashing without tweaks for now.
pub fn sigma(block: Block, cipher: &FixedKeyAes) -> Block {
    let tweak = Block::new([0; 16]);
    cipher.tccr(tweak, block);
    block
}
