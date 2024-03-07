//! Messages for the Ferret protocol.
use mpz_core::Block;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The seed to generate Lpn matrix.
pub struct LpnMatrixSeed {
    /// The seed.
    pub seed: Block,
}
