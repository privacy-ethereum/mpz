use std::fmt::Display;

/// Ferret sender error.
#[derive(Debug, thiserror::Error)]
pub struct SenderError {
    kind: SenderErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SenderError {
    pub(crate) fn state(msg: impl Into<String>) -> Self {
        Self {
            kind: SenderErrorKind::State,
            source: Some(msg.into().into()),
        }
    }

    pub(crate) fn io(msg: impl Into<String>) -> Self {
        Self {
            kind: SenderErrorKind::Io,
            source: Some(msg.into().into()),
        }
    }
}

#[derive(Debug)]
enum SenderErrorKind {
    Io,
    State,
    Core,
    Rcot,
    Mpcot,
}

impl Display for SenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            SenderErrorKind::Io => f.write_str("io error")?,
            SenderErrorKind::State => f.write_str("state error")?,
            SenderErrorKind::Core => f.write_str("core error")?,
            SenderErrorKind::Rcot => f.write_str("rcot error")?,
            SenderErrorKind::Mpcot => f.write_str("mpcot error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)
        } else {
            Ok(())
        }
    }
}

impl From<std::io::Error> for SenderError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: SenderErrorKind::Io,
            source: Some(Box::new(err)),
        }
    }
}

impl From<mpz_ot_core::ferret::error::SenderError> for SenderError {
    fn from(err: mpz_ot_core::ferret::error::SenderError) -> Self {
        Self {
            kind: SenderErrorKind::Core,
            source: Some(Box::new(err)),
        }
    }
}

impl From<crate::OTError> for SenderError {
    fn from(err: crate::OTError) -> Self {
        Self {
            kind: SenderErrorKind::Rcot,
            source: Some(Box::new(err)),
        }
    }
}

impl From<MPCOTError> for SenderError {
    fn from(err: MPCOTError) -> Self {
        Self {
            kind: SenderErrorKind::Mpcot,
            source: Some(Box::new(err)),
        }
    }
}

impl From<SenderError> for crate::OTError {
    fn from(err: SenderError) -> Self {
        crate::OTError::SenderError(Box::new(err))
    }
}

/// Ferret receiver error.
#[derive(Debug, thiserror::Error)]
pub struct ReceiverError {
    kind: ReceiverErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ReceiverError {
    pub(crate) fn state(msg: impl Into<String>) -> Self {
        Self {
            kind: ReceiverErrorKind::State,
            source: Some(msg.into().into()),
        }
    }

    pub(crate) fn io(msg: impl Into<String>) -> Self {
        Self {
            kind: ReceiverErrorKind::Io,
            source: Some(msg.into().into()),
        }
    }
}

#[derive(Debug)]
enum ReceiverErrorKind {
    Io,
    State,
    Core,
    Rcot,
    Mpcot,
}

impl Display for ReceiverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ReceiverErrorKind::Io => f.write_str("io error")?,
            ReceiverErrorKind::State => f.write_str("state error")?,
            ReceiverErrorKind::Core => f.write_str("core error")?,
            ReceiverErrorKind::Rcot => f.write_str("rcot error")?,
            ReceiverErrorKind::Mpcot => f.write_str("mpcot error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)
        } else {
            Ok(())
        }
    }
}

impl From<std::io::Error> for ReceiverError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: ReceiverErrorKind::Io,
            source: Some(Box::new(err)),
        }
    }
}

impl From<mpz_ot_core::ferret::error::ReceiverError> for ReceiverError {
    fn from(err: mpz_ot_core::ferret::error::ReceiverError) -> Self {
        Self {
            kind: ReceiverErrorKind::Core,
            source: Some(Box::new(err)),
        }
    }
}

impl From<crate::OTError> for ReceiverError {
    fn from(err: crate::OTError) -> Self {
        Self {
            kind: ReceiverErrorKind::Rcot,
            source: Some(Box::new(err)),
        }
    }
}

impl From<MPCOTError> for ReceiverError {
    fn from(err: MPCOTError) -> Self {
        Self {
            kind: ReceiverErrorKind::Mpcot,
            source: Some(Box::new(err)),
        }
    }
}

impl From<ReceiverError> for crate::OTError {
    fn from(err: ReceiverError) -> Self {
        crate::OTError::ReceiverError(Box::new(err))
    }
}

mod mpcot {
    use super::*;

    /// MPCOT error.
    #[derive(Debug, thiserror::Error)]
    pub(crate) struct MPCOTError {
        kind: ErrorKind,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    }

    #[derive(Debug)]
    enum ErrorKind {
        Io,
        Core,
        Rcot,
        Spcot,
    }

    impl Display for MPCOTError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.kind {
                ErrorKind::Io => f.write_str("io error")?,
                ErrorKind::Core => f.write_str("core error")?,
                ErrorKind::Rcot => f.write_str("rcot error")?,
                ErrorKind::Spcot => f.write_str("spcot error")?,
            }

            if let Some(source) = &self.source {
                write!(f, " caused by: {}", source)
            } else {
                Ok(())
            }
        }
    }

    impl From<std::io::Error> for MPCOTError {
        fn from(err: std::io::Error) -> Self {
            Self {
                kind: ErrorKind::Io,
                source: Some(Box::new(err)),
            }
        }
    }

    impl From<mpz_ot_core::ferret::mpcot::error::SenderError> for MPCOTError {
        fn from(err: mpz_ot_core::ferret::mpcot::error::SenderError) -> Self {
            Self {
                kind: ErrorKind::Core,
                source: Some(Box::new(err)),
            }
        }
    }

    impl From<mpz_ot_core::ferret::mpcot::error::ReceiverError> for MPCOTError {
        fn from(err: mpz_ot_core::ferret::mpcot::error::ReceiverError) -> Self {
            Self {
                kind: ErrorKind::Core,
                source: Some(Box::new(err)),
            }
        }
    }

    impl From<SPCOTError> for MPCOTError {
        fn from(err: SPCOTError) -> Self {
            Self {
                kind: ErrorKind::Spcot,
                source: Some(Box::new(err)),
            }
        }
    }

    impl From<crate::OTError> for MPCOTError {
        fn from(err: crate::OTError) -> Self {
            Self {
                kind: ErrorKind::Rcot,
                source: Some(Box::new(err)),
            }
        }
    }
}
pub(crate) use mpcot::MPCOTError;

mod spcot {
    use super::*;

    /// SPCOT error.
    #[derive(Debug, thiserror::Error)]
    pub(crate) struct SPCOTError {
        kind: ErrorKind,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    }

    #[derive(Debug)]
    enum ErrorKind {
        Io,
        Core,
        Rcot,
    }

    impl Display for SPCOTError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.kind {
                ErrorKind::Io => f.write_str("io error")?,
                ErrorKind::Core => f.write_str("core error")?,
                ErrorKind::Rcot => f.write_str("rcot error")?,
            }

            if let Some(source) = &self.source {
                write!(f, " caused by: {}", source)
            } else {
                Ok(())
            }
        }
    }

    impl From<std::io::Error> for SPCOTError {
        fn from(err: std::io::Error) -> Self {
            Self {
                kind: ErrorKind::Io,
                source: Some(Box::new(err)),
            }
        }
    }

    impl From<mpz_ot_core::ferret::spcot::error::SenderError> for SPCOTError {
        fn from(err: mpz_ot_core::ferret::spcot::error::SenderError) -> Self {
            Self {
                kind: ErrorKind::Core,
                source: Some(Box::new(err)),
            }
        }
    }

    impl From<mpz_ot_core::ferret::spcot::error::ReceiverError> for SPCOTError {
        fn from(err: mpz_ot_core::ferret::spcot::error::ReceiverError) -> Self {
            Self {
                kind: ErrorKind::Core,
                source: Some(Box::new(err)),
            }
        }
    }

    impl From<crate::OTError> for SPCOTError {
        fn from(err: crate::OTError) -> Self {
            Self {
                kind: ErrorKind::Rcot,
                source: Some(Box::new(err)),
            }
        }
    }
}
pub(crate) use spcot::SPCOTError;
