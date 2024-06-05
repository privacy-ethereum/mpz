//! Secure two-party (2PC) multiplication-to-addition (M2A) and addition-to-multiplication (A2M)
//! algorithms, both with semi-honest security.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

pub mod ideal;
pub mod msgs;

mod a2m;
mod m2a;

pub use a2m::{a2m_convert_receiver, a2m_convert_sender, A2MMasks};
pub use m2a::m2a_convert;

use std::{error::Error, fmt::Display};

/// A share conversion error.
#[derive(Debug, thiserror::Error)]
pub struct ShareConversionError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
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

impl Display for ShareConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::UnequalLength => write!(f, "Unequal Length Error"),
        }?;

        if let Some(source) = self.source.as_ref() {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    UnequalLength,
}
