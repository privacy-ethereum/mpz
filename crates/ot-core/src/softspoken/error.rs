/// Errors that can occur when using the SoftSpoken sender.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SenderError {
    #[error("invalid state: expected {0}")]
    InvalidState(String),
    #[error("count mismatch: expected {expected}, got {actual}")]
    CountMismatch { expected: usize, actual: usize },
    #[error("invalid extend")]
    InvalidExtend,
    #[error("consistency check failed")]
    ConsistencyCheckFailed,
    #[error("not enough OTs are set up: expected {expected}, actual {actual}")]
    InsufficientSetup { expected: usize, actual: usize },
    #[error("chi seed is not set")]
    ChiNotSet,
}

/// Errors that can occur when using the SoftSpoken receiver.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ReceiverError {
    #[error("invalid state: expected {0}")]
    InvalidState(String),
    #[error("not enough OTs are set up: expected {expected}, actual {actual}")]
    InsufficientSetup { expected: usize, actual: usize },
}
