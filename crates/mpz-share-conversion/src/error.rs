use core::fmt;
use mpz_ole::OLEError;
use mpz_share_conversion_core::ShareConversionError as ShareConversionCoreError;
use std::error::Error;
use std::io::Error as IOError;

/// A share conversion error.
#[derive(Debug, thiserror::Error)]
pub struct ShareConversionError {
    #[allow(dead_code)]
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ShareConversionError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    Ole,
    IO,
    ShareConversionCore,
}

impl fmt::Display for ShareConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Ole => write!(f, "OLE Error"),
            ErrorKind::IO => write!(f, "IO Error"),
            ErrorKind::ShareConversionCore => write!(f, "Core Error"),
        }?;

        if let Some(source) = self.source.as_ref() {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

impl From<OLEError> for ShareConversionError {
    fn from(value: OLEError) -> Self {
        Self::new(ErrorKind::Ole, value)
    }
}

impl From<ShareConversionCoreError> for ShareConversionError {
    fn from(value: ShareConversionCoreError) -> Self {
        Self::new(ErrorKind::ShareConversionCore, value)
    }
}

impl From<IOError> for ShareConversionError {
    fn from(value: IOError) -> Self {
        Self::new(ErrorKind::IO, value)
    }
}
