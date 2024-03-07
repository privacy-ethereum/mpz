use crate::OTError;

/// A Chou-Orlandi sender error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SenderError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    CoreError(#[from] mpz_ot_core::chou_orlandi::SenderError),
    #[error("{0}")]
    StateError(String),
    #[error("coin-toss error: {0}")]
    CointossError(#[from] mpz_cointoss::CointossError),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

impl From<SenderError> for OTError {
    fn from(err: SenderError) -> Self {
        match err {
            SenderError::IOError(e) => e.into(),
            e => OTError::SenderError(Box::new(e)),
        }
    }
}

impl From<crate::chou_orlandi::sender::StateError> for SenderError {
    fn from(err: crate::chou_orlandi::sender::StateError) -> Self {
        SenderError::StateError(err.to_string())
    }
}

/// A Chou-Orlandi receiver error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ReceiverError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    CoreError(#[from] mpz_ot_core::chou_orlandi::ReceiverError),
    #[error("{0}")]
    StateError(String),
    #[error("coin-toss error: {0}")]
    CointossError(#[from] mpz_cointoss::CointossError),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

impl From<ReceiverError> for OTError {
    fn from(err: ReceiverError) -> Self {
        match err {
            ReceiverError::IOError(e) => e.into(),
            e => OTError::ReceiverError(Box::new(e)),
        }
    }
}

impl From<crate::chou_orlandi::receiver::StateError> for ReceiverError {
    fn from(err: crate::chou_orlandi::receiver::StateError) -> Self {
        ReceiverError::StateError(err.to_string())
    }
}
