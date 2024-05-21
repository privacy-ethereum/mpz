//! IO wrappers for Oblivious Linear Function Evaluation (OLE).

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

use async_trait::async_trait;
use mpz_common::Context;
use mpz_fields::Field;
use mpz_ole_core::OLEError as OLECoreError;
use mpz_ot::OTError;
use std::{error::Error, fmt::Debug};

pub mod ideal;
pub mod rot;

/// Batch OLE Sender.
///
/// The sender inputs field elements `a_k` and gets outputs `x_k`, such that
/// `y_k = a_k * b_k + x_k` holds, where `b_k` and `y_k` are the [`OLEReceiver`]'s inputs and outputs
/// respectively.
#[async_trait]
pub trait OLESender<C: Context, F: Field> {
    /// Sends his masked inputs to the [`OLEReceiver`].
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context, which provides IO channels.
    /// * `a_k` - The sender's OLE inputs.
    ///
    /// # Returns
    ///
    /// * The sender's OLE outputs `x_k`.
    async fn send(&mut self, ctx: &mut C, a_k: Vec<F>) -> Result<Vec<F>, OLEError>;
}

/// Batch OLE Receiver.
///
/// The receiver inputs field elements `b_k` and gets outputs `y_k`, such that
/// `y_k = a_k * b_k + x_k` holds, where `a_k` and `x_k` are the [`OLESender`]'s inputs and outputs
/// respectively.
#[async_trait]
pub trait OLEReceiver<C: Context, F: Field> {
    /// Receives the masked inputs of the [`OLESender`].
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context, which provides IO channels.
    /// * `b_k` - The receiver's OLE inputs.
    ///
    /// # Returns
    ///
    /// * The receiver's OLE outputs `y_k`.
    async fn receive(&mut self, ctx: &mut C, inputs: Vec<F>) -> Result<Vec<F>, OLEError>;
}

/// An OLE error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OLEError {
    #[error(transparent)]
    OT(#[from] OTError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    OLECoreError(#[from] OLECoreError),
    #[error("Not enough OLEs available")]
    InsufficientOLEs,
    #[error(transparent)]
    Message(Box<dyn Error + Send + 'static>),
}
