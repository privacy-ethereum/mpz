//! This crate provides IO wrappers for implementations of different oblivious linear evaluation with errors (OLEe) flavors.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

use async_trait::async_trait;
use mpz_core::ProtocolMessage;
use mpz_ole_core::OLECoreError;
use mpz_ot::OTError;
use mpz_share_conversion_core::fields::Field;
use msg::{OLEeMessageError, ROLEeMessageError};
use std::{error::Error, fmt::Debug};
use utils_aio::{sink::IoSink, stream::IoStream};

pub mod ideal;
pub mod msg;
pub mod ole;
pub mod role;

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
    #[error(transparent)]
    Message(Box<dyn Error + Send + 'static>),
}

impl<T: Debug + Send + 'static, F: Field> From<OLEeMessageError<T, F>> for OLEError {
    fn from(value: OLEeMessageError<T, F>) -> Self {
        OLEError::Message(Box::new(value) as Box<dyn Error + Send + 'static>)
    }
}

impl<T: Debug + Send + 'static, F: Field> From<ROLEeMessageError<T, F>> for OLEError {
    fn from(value: ROLEeMessageError<T, F>) -> Self {
        OLEError::Message(Box::new(value) as Box<dyn Error + Send + 'static>)
    }
}

/// An OLE with errors evaluator.
///
/// The evaluator determines the function inputs and obliviously evaluates the linear functions
/// which depend on the inputs of [`OLEeProvide`]. The evaluator can introduce additive errors to
/// the evaluation.
#[async_trait]
pub trait OLEeEvaluate<F: Field>: ProtocolMessage {
    /// Evaluates linear functions at specific points obliviously.
    ///
    /// The functions being evaluated are outputs_k = inputs_k * provider-factors_k +
    /// provider-offsets_k. Returns the outputs of the functions.
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the provider.
    /// * `stream` - The IO stream from the provider.
    /// * `inputs` - The points where to evaluate the functions.
    async fn evaluate<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, OLEError>;
}

/// An OLE with errors provider.
///
/// The provider determines with his inputs which linear functions are to be evaluated by
/// [`OLEeEvaluate`]. The provider can introduce additive errors to the evaluation.
#[async_trait]
pub trait OLEeProvide<F: Field>: ProtocolMessage {
    /// Provides the linear functions which are to be evaluated obliviously.
    ///
    /// The functions being evaluated are evaluator-outputs_k = evaluator-inputs_k * factors_k +
    /// offsets_k. Returns the offsets of the functions.
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the evaluator.
    /// * `stream` - The IO stream from the evaluator.
    /// * `factors` - Provides the slopes for the linear functions.
    async fn provide<Si: IoSink<Self::Msg> + Send + Unpin, St: IoStream<Self::Msg> + Send + Unpin>(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        factors: Vec<F>,
    ) -> Result<Vec<F>, OLEError>;
}

/// A random OLE with errors (ROLEe) evaluator.
///
/// The evaluator obliviously evaluates random linear functions at random values. The evaluator
/// can introduce additive errors to the evaluation.
#[async_trait]
pub trait RandomOLEeEvaluate<F: Field>: ProtocolMessage {
    /// Evaluates random linear functions at random points obliviously.
    ///
    /// The function being evaluated is outputs_k = random-inputs_k * random-factors_k +
    /// random-offsets_k. Returns (random-inputs, outputs).
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the provider.
    /// * `stream` - The IO stream from the provider.
    /// * `count` - The number of functions to evaluate.
    async fn evaluate_random<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        count: usize,
    ) -> Result<(Vec<F>, Vec<F>), OLEError>;
}

/// A random OLE with errors (ROLEe) provider.
///
/// The provider receives random linear functions. The provider can introduce additive errors to the evaluation.
#[async_trait]
pub trait RandomOLEeProvide<F: Field>: ProtocolMessage {
    /// Provides the random functions which are to be evaluated obliviously.
    ///
    /// The function being evaluated is evaluator-outputs_k = random-inputs_k * random-factors_k +
    /// random-offsets_k. Returns (random-factors, random-offsets).
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the evaluator.
    /// * `stream` - The IO stream from the evaluator.
    /// * `count` - The number of functions to provide.
    async fn provide_random<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        count: usize,
    ) -> Result<(Vec<F>, Vec<F>), OLEError>;
}

/// Workaround because of feature `generic_const_exprs` not available in stable.
///
/// This is used to check at compile-time that the correct const-generic implementation is used for
/// a specific field.
struct Check<const N: usize, F: Field>(std::marker::PhantomData<F>);

impl<const N: usize, F: Field> Check<N, F> {
    const IS_BITSIZE_CORRECT: () = assert!(
        N as u32 == F::BIT_SIZE / 8,
        "Wrong bit size used for field. You need to use `F::BIT_SIZE` for N."
    );
}
