//! Messages for the SPCOT protocol

use mpz_core::{hash::Hash, Block};
use serde::{Deserialize, Serialize};

/// An SPCOT message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Message<CotMsg> {
    CotMsg(CotMsg),
    MaskBits(MaskBits),
    ExtendFromSender(ExtendFromSender),
    CheckFromReceiver(CheckFromReceiver),
    CheckFromSender(CheckFromSender),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The mask bits sent by the receiver.
pub struct MaskBits {
    /// The mask bits sent by the receiver.
    pub bs: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The extend messages sent by the sender.
pub struct ExtendFromSender {
    /// The mask `m0` and `m1`.
    pub ms: Vec<[Block; 2]>,
    /// The sum of the ggm tree leaves and delta.
    pub sum: Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The consistency check message sent from the receiver.
pub struct CheckFromReceiver {
    /// The `x'` from the receiver.
    pub x_prime: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The consistency check message sent from the sender.
pub struct CheckFromSender {
    /// The hashed `V` from the sender.
    pub hashed_v: Hash,
}
