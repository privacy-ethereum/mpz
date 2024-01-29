//! Implementations of different oblivious linear evaluation (OLE) protocols.
//!
//! An OLE allows a party to obliviously evaluate a linear function. Given party P_A with input x
//! and party P_B with input a and b, party P_A takes the role of the evaluator and obliviously
//! evaluates the function y = a * x + b, i.e. P_A learns y and nothing else and P_B learns nothing.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

use async_trait::async_trait;
use mpz_core::ProtocolMessage;
use mpz_ot::OTError;
use mpz_share_conversion_core::fields::Field;
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
    #[error("Error during ROLEe protocol: {0}")]
    ROLEeError(String),
}

/// An OLE with errors (OLEe) evaluator.
///
/// The evaluator provides inputs and obliviously evaluates the linear functions depending on the
/// inputs of the [`OLEeProvide`]. The provider can introduce additive errors to the evaluation.
#[async_trait]
pub trait OLEeEvaluate<F: Field>: ProtocolMessage {
    /// Evaluates linear functions at specific points obliviously.
    ///
    /// The function being evaluated is outputs_i = inputs_i * provider-factors_i +
    /// provider-summands_i.
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the receiver.
    /// * `stream` - The IO stream from the receiver.
    /// * `inputs` - The points where to evaluate the function.
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
/// The provider determines with his inputs which linear functions are to be evaluated by the
/// [`OLEeEvaluate`]. The provider can introduce additive errors to the evaluation.
#[async_trait]
pub trait OLEeProvide<F: Field>: ProtocolMessage {
    /// Provides the functions which are to be evaluated obliviously.
    ///
    /// The function being evaluated is evaluator-outputs_i = evaluator-inputs_i * factors_i +
    /// summands_i. Returns the summands.
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the receiver.
    /// * `stream` - The IO stream from the receiver.
    /// * `factors` - Provides the slopes for the linear functions.
    async fn provide<Si: IoSink<Self::Msg> + Send + Unpin, St: IoStream<Self::Msg> + Send + Unpin>(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        factors: Vec<F>,
    ) -> Result<Vec<F>, OLEError>;
}

/// A Random OLE with errors (ROLEe) evaluator.
///
/// The evaluator obliviously evaluates random linear functions at random values. The provider
/// can introduce additive errors to the evaluation.
#[async_trait]
pub trait RandomOLEeEvaluate<F: Field>: ProtocolMessage {
    /// Evaluates random linear functions at random points obliviously.
    ///
    /// The function being evaluated is outputs_i = random-inputs_i * random-factors_i +
    /// random-summands_i. Returns (random-inputs, outputs).
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the receiver.
    /// * `stream` - The IO stream from the receiver.
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

/// A Random OLE with errors (ROLEe) provider.
///
/// The provider receives random linear functions. The provider can introduce additive errors to the evaluation.
#[async_trait]
pub trait RandomOLEeProvide<F: Field>: ProtocolMessage {
    /// Provides the random functions which are to be evaluated obliviously.
    ///
    /// The function being evaluated is evaluator-outputs_i = random-inputs_i * random-factors_i +
    /// random-summands_i. Returns (random-factors, random-summands).
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the receiver.
    /// * `stream` - The IO stream from the receiver.
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
        N as u32 == F::BIT_SIZE,
        "Wrong bit size used for field. You need to use `F::BIT_SIZE` for N."
    );
}
