//! Errors that can occur when using the Ferret protocol.

/// Errors that can occur when using the Ferret sender.
#[derive(Debug, thiserror::Error)]
#[error("invalid input: expected {0}")]
pub struct SenderError(pub String);

/// Errors that can occur when using the Ferret receiver.
#[derive(Debug, thiserror::Error)]
#[error("invalid input: expected {0}")]
pub struct ReceiverError(pub String);
