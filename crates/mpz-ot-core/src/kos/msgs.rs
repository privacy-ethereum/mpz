//! Messages for the KOS15 protocol.

use mpz_core::Block;
use serde::{Deserialize, Serialize};

use crate::TransferId;

/// Extension message sent by the receiver to agree upon the number of OTs to
/// set up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartExtend {
    /// The number of OTs to set up.
    pub count: usize,
}

/// Extension message sent by the receiver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Extend {
    /// The receiver's extension vectors.
    pub us: Vec<u8>,
}

impl Extend {
    /// Returns an iterator over the chunks of the message.
    pub fn into_chunks(self, chunk_size: usize) -> ExtendChunks {
        ExtendChunks {
            chunk_size,
            us: self.us.into_iter(),
        }
    }
}

/// Iterator over the chunks of an extension message.
pub struct ExtendChunks {
    chunk_size: usize,
    us: <Vec<u8> as IntoIterator>::IntoIter,
}

impl Iterator for ExtendChunks {
    type Item = Extend;

    fn next(&mut self) -> Option<Self::Item> {
        if self.us.len() == 0 {
            None
        } else {
            Some(Extend {
                us: self.us.by_ref().take(self.chunk_size).collect::<Vec<_>>(),
            })
        }
    }
}

/// Sender payload message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SenderPayload {
    /// Transfer ID
    pub id: TransferId,
    /// Sender's ciphertexts
    pub ciphertexts: Ciphertexts,
}

/// OT ciphertexts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Ciphertexts {
    /// Messages encrypted with XOR
    Blocks {
        /// Sender's ciphertexts
        ciphertexts: Vec<Block>,
    },
    /// Messages encrypted with stream cipher
    Bytes {
        /// Sender's ciphertexts
        ciphertexts: Vec<u8>,
        /// The IV used for encryption.
        iv: Vec<u8>,
        /// The length of each message in bytes.
        length: u32,
    },
}
