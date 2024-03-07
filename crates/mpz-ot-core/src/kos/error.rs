/// Errors that can occur when using the KOS15 sender.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SenderError {
    #[error("invalid state: expected {0}")]
    InvalidState(String),
    #[error("invalid count, must be a multiple of 64: {0}")]
    InvalidCount(usize),
    #[error("count mismatch: expected {0}, got {1}")]
    CountMismatch(usize, usize),
    #[error("id mismatch: expected {0}, got {1}")]
    IdMismatch(u32, u32),
    #[error("invalid extend")]
    InvalidExtend,
    #[error("consistency check failed")]
    ConsistencyCheckFailed,
    #[error("not enough OTs are setup: expected {0}, actual {1}")]
    InsufficientSetup(usize, usize),
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
    IdMismatch(u32, u32),
    #[error("not enough OTs are setup: expected {0}, actual {1}")]
    InsufficientSetup(usize, usize),
    #[error("invalid payload")]
    InvalidPayload(String),
    #[error(transparent)]
    ReceiverVerifyError(#[from] ReceiverVerifyError),
}

/// Errors that can occur during verification of the sender's messages.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ReceiverVerifyError {
    #[error("tape was not recorded")]
    TapeNotRecorded,
    #[error("invalid transfer id: {0}")]
    InvalidTransferId(u32),
    #[error("payload inconsistent")]
    InconsistentPayload,
}
