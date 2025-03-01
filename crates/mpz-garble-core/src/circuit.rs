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


/// An authenticated garbled gate
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AuthEncryptedGate(#[serde(with = "serde_arrays")] pub(crate) [[Block; 2]; 4]);

impl AuthEncryptedGate {
    /// Creates a new authenticated encrypted gate from a 4-Block array.
    pub fn new(inner: [[Block; 2]; 4]) -> Self {
        Self(inner)
    }

    /// Constructs an `AuthEncryptedGate` by hashing two input labels and offset.
    pub fn new_with_labels(l1: Block, l2: Block, delta: Block, cipher: &FixedKeyAes) -> Self {

        let mut a = [l1, l1 ^ delta];
        let mut b = [l2, l2 ^ delta];

        a[0] = sigma(a[0], cipher);
        a[1] = sigma(a[1], cipher);
        b[0] = sigma(sigma(b[0], cipher), cipher);
        b[1] = sigma(sigma(b[1], cipher), cipher);

        let mut h = [[Block::default(); 2]; 4];

        h[0][0] = a[0] ^ b[0];
        h[0][1] = h[0][0];

        h[1][0] = a[0] ^ b[1];
        h[1][1] = h[1][0];

        h[2][0] = a[1] ^ b[0];
        h[2][1] = h[2][0];

        h[3][0] = a[1] ^ b[1];
        h[3][1] = h[3][0];

        Self(h)
    }
}

impl Index<usize> for AuthEncryptedGate {
    type Output = [Block; 2];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// A batch of authenticated encrypted gates.
///
/// # Parameters
///
/// - `N`: The size of a batch.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthEncryptedGateBatch<const N: usize = DEFAULT_BATCH_SIZE>(
    #[serde(with = "serde_arrays")] [AuthEncryptedGate; N],
);

impl<const N: usize> AuthEncryptedGateBatch<N> {
    /// Creates a new batch of authenticated encrypted gates.
    pub fn new(batch: [AuthEncryptedGate; N]) -> Self {
        Self(batch)
    }

    /// Returns the inner array.
    pub fn into_array(self) -> [AuthEncryptedGate; N] {
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
