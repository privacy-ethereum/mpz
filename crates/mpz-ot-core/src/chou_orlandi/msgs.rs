//! Messages for the Chou-Orlandi protocol.

use curve25519_dalek::RistrettoPoint;
use mpz_core::Block;
use serde::{Deserialize, Serialize};

/// Sender setup message.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SenderSetup {
    /// The sender's public key
    pub public_key: RistrettoPoint,
}

/// Sender payload message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SenderPayload {
    /// The sender's ciphertexts
    pub payload: Vec<[Block; 2]>,
}

/// Receiver payload message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiverPayload {
    /// The receiver's blinded choices.
    pub blinded_choices: Vec<RistrettoPoint>,
}

/// Receiver reveal message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverReveal {
    /// The receiver's choices.
    pub choices: Vec<u8>,
}
