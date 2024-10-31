use crate::TransferId;

/// Errors that can occur when using the KOS15 sender.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SenderError {
    #[error("invalid state: expected {0}")]
    InvalidState(String),
    #[error("invalid count, must be a multiple of 64: {0}")]
    InvalidCount(usize),
    #[error("count mismatch: expected {expected}, got {actual}")]
    CountMismatch { expected: usize, actual: usize },
    #[error("id mismatch: expected {0}, got {1}")]
    IdMismatch(TransferId, TransferId),
    #[error("invalid extend")]
    InvalidExtend,
    #[error("consistency check failed")]
    ConsistencyCheckFailed,
    #[error("not enough OTs are setup: expected {expected}, actual {actual}")]
    InsufficientSetup { expected: usize, actual: usize },
}

/// Errors that can occur when using the KOS15 receiver.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ReceiverError {
    #[error("invalid state: expected {0}")]
    InvalidState(String),
    #[error("invalid count, must be a multiple of 64: {0}")]
    InvalidCount(usize),
    #[error("count mismatch: expected {0}, got {1}")]
    CountMismatch(usize, usize),
    #[error("id mismatch: expected {0}, got {1}")]
    IdMismatch(TransferId, TransferId),
    #[error("not enough OTs are setup: expected {expected}, actual {actual}")]
    InsufficientSetup { expected: usize, actual: usize },
    #[error("invalid payload")]
    InvalidPayload(String),
}
