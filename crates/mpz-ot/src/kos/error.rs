use crate::OTError;

/// A KOS sender error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SenderError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    CoreError(#[from] mpz_ot_core::kos::SenderError),
    #[error(transparent)]
    BaseOTError(#[from] crate::OTError),
    #[error("coin-toss error: {0}")]
    CointossError(#[from] mpz_cointoss::CointossError),
    #[error("{0}")]
    StateError(String),
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error("{0}")]
    Other(String),
}

impl From<SenderError> for OTError {
    fn from(err: SenderError) -> Self {
        match err {
            SenderError::IOError(e) => e.into(),
            e => OTError::SenderError(Box::new(e)),
        }
    }
}

impl From<crate::kos::SenderStateError> for SenderError {
    fn from(err: crate::kos::SenderStateError) -> Self {
        SenderError::StateError(err.to_string())
    }
}

impl From<mpz_ot_core::kos::SenderError> for OTError {
    fn from(err: mpz_ot_core::kos::SenderError) -> Self {
        SenderError::from(err).into()
    }
}

/// A KOS receiver error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ReceiverError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    CoreError(#[from] mpz_ot_core::kos::ReceiverError),
    #[error(transparent)]
    BaseOTError(#[from] crate::OTError),
    #[error("coin-toss error: {0}")]
    CointossError(#[from] mpz_cointoss::CointossError),
    #[error("{0}")]
    StateError(String),
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error(transparent)]
    VerifyError(#[from] ReceiverVerifyError),
    #[error("{0}")]
    Other(String),
}

impl From<ReceiverError> for OTError {
    fn from(err: ReceiverError) -> Self {
        match err {
            ReceiverError::IOError(e) => e.into(),
            e => OTError::ReceiverError(Box::new(e)),
        }
    }
}

impl From<crate::kos::ReceiverStateError> for ReceiverError {
    fn from(err: crate::kos::ReceiverStateError) -> Self {
        ReceiverError::StateError(err.to_string())
    }
}

impl From<mpz_ot_core::kos::ReceiverError> for OTError {
    fn from(err: mpz_ot_core::kos::ReceiverError) -> Self {
        ReceiverError::from(err).into()
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ReceiverVerifyError {
    #[error("delta value is not inconsistent")]
    InconsistentDelta,
}
