//! Errors that can occur when using the MPCOT protocol.

use crate::ferret::cuckoo::{BucketError, CuckooHashError};
/// Errors that can occur when using the MPCOT sender.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SenderError {
    #[error("invalid input: expected {0}")]
    InvalidInput(String),
    #[error(transparent)]
    BucketError(#[from] BucketError),
}

/// Errors that can occur when using the MPCOT receiver.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ReceiverError {
    #[error("invalid input: expected {0}")]
    InvalidInput(String),
    #[error(transparent)]
    CuckooHashError(#[from] CuckooHashError),
    #[error(transparent)]
    BucketError(#[from] BucketError),
}
