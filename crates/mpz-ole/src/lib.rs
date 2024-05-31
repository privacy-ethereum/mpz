//! IO wrappers for Oblivious Linear Function Evaluation (OLE).

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

use async_trait::async_trait;
use mpz_common::Context;
use mpz_fields::{Field, FieldError};
use mpz_ole_core::OLEError as OLECoreError;
use mpz_ot::OTError;
use std::{
    error::Error,
    fmt::{Debug, Display},
    io::Error as IOError,
};

#[cfg(feature = "ideal")]
pub mod ideal;
pub mod rot;

/// Batch OLE Sender.
///
/// The sender inputs field elements `a_k` and gets outputs `x_k`, such that
/// `y_k = a_k * b_k + x_k` holds, where `b_k` and `y_k` are the [`OLEReceiver`]'s inputs and outputs
/// respectively.
#[async_trait]
pub trait OLESender<Ctx: Context, F: Field> {
    /// Sends his masked inputs to the [`OLEReceiver`].
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context.
    /// * `inputs` - The sender's OLE inputs.
    ///
    /// # Returns
    ///
    /// * The sender's OLE outputs `x_k`.
    async fn send(&mut self, ctx: &mut Ctx, inputs: Vec<F>) -> Result<Vec<F>, OLEError>;
}

/// Batch OLE Receiver.
///
/// The receiver inputs field elements `b_k` and gets outputs `y_k`, such that
/// `y_k = a_k * b_k + x_k` holds, where `a_k` and `x_k` are the [`OLESender`]'s inputs and outputs
/// respectively.
#[async_trait]
pub trait OLEReceiver<Ctx: Context, F: Field> {
    /// Receives the masked inputs of the [`OLESender`].
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context.
    /// * `inputs` - The receiver's OLE inputs.
    ///
    /// # Returns
    ///
    /// * The receiver's OLE outputs `y_k`.
    async fn receive(&mut self, ctx: &mut Ctx, inputs: Vec<F>) -> Result<Vec<F>, OLEError>;
}

/// An OLE error.
#[derive(Debug, thiserror::Error)]
pub struct OLEError {
    kind: OLEErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl OLEError {
    fn new<E>(kind: OLEErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

impl Display for OLEError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            OLEErrorKind::OT => write!(f, "OT Error"),
            OLEErrorKind::IO => write!(f, "IO Error"),
            OLEErrorKind::Core => write!(f, "OLE Core Error"),
            OLEErrorKind::Field => write!(f, "FieldError"),
            OLEErrorKind::InsufficientOLEs => write!(f, "Insufficient OLEs"),
        }?;

        if let Some(source) = self.source.as_ref() {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum OLEErrorKind {
    OT,
    IO,
    Core,
    Field,
    InsufficientOLEs,
}

impl From<OTError> for OLEError {
    fn from(value: OTError) -> Self {
        Self::new(OLEErrorKind::OT, value)
    }
}

impl From<IOError> for OLEError {
    fn from(value: IOError) -> Self {
        Self::new(OLEErrorKind::IO, value)
    }
}

impl From<OLECoreError> for OLEError {
    fn from(value: OLECoreError) -> Self {
        Self::new(OLEErrorKind::Core, value)
    }
}

impl From<FieldError> for OLEError {
    fn from(value: FieldError) -> Self {
        Self::new(OLEErrorKind::Field, value)
    }
}
