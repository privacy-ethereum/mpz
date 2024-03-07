//! Messages for the MPCOT protocol.

use mpz_core::Block;
use serde::{Deserialize, Serialize};

/// An MPCOT message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Message<SpcotMsg> {
    SpcotMsg(SpcotMsg),
    HashSeed(HashSeed),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The seed to generate Cuckoo hashes.
pub struct HashSeed {
    /// The seed.
    pub seed: Block,
}
