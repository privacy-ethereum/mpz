use core::fmt;

/// A share conversion error.
#[derive(Debug, thiserror::Error)]
pub struct ShareConversionError {
    #[allow(dead_code)]
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

#[derive(Debug)]
pub(crate) enum ErrorKind {}

impl fmt::Display for ShareConversionError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
