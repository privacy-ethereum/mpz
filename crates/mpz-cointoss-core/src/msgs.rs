//! Coin-toss protocol messages.

use serde::{Deserialize, Serialize};

use mpz_core::{commit::Decommitment, hash::Hash, Block};

/// The coin-toss sender's commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderCommitment {
    /// The commitment to the random seeds.
    pub commitment: Hash,
}

/// The coin-toss sender's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderPayload {
    /// The decommitment to the random seeds.
    pub decommitment: Decommitment<Vec<Block>>,
}

/// The coin-toss receiver's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverPayload {
    /// The receiver's random seeds.
    pub seeds: Vec<Block>,
}
