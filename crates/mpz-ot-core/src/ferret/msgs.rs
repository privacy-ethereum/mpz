//! Ferret protocol messages.

use mpz_core::Block;
use serde::{Deserialize, Serialize};

/// The seed to generate Lpn matrix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LpnMatrixSeed {
    /// The seed.
    pub seed: Block,
}
