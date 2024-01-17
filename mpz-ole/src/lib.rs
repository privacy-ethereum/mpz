//! Implementations of oblivious linear evaluation (OLE) protocols.
//!
//! An OLE allows a party to obliviously evaluate a linear function. Given party P_A with input x
//! and party P_B with input a and b, party P_A takes the role of the evaluator and obliviously
//! evaluates the function y = a * x + b, i.e. P_A learns y and nothing else and P_B learns nothing.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

use async_trait::async_trait;
use mpz_core::ProtocolMessage;
use mpz_share_conversion_core::fields::Field;
use utils_aio::{sink::IoSink, stream::IoStream};

/// An OLE error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OLEError {
    #[error("")]
    Error,
}

/// An OLE with errors (OLEe) evaluator.
///
/// The evaluator provides inputs and obliviously evaluates the linear functions depending on the
/// inputs of the [`OLEeProvider`]. The provider can introduce additive errors to the evaluation.
#[async_trait]
pub trait OLEeEvaluator: ProtocolMessage {
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
        F: Field,
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
/// [`OLEeEvaluator`]. The provider can introduce additive errors to the evaluation.
#[async_trait]
pub trait OLEeProvider: ProtocolMessage {
    /// Provides the functions which are to be evaluated obliviously.
    ///
    /// The function being evaluated is evaluator-outputs_i = evaluator-inputs_i * factors_i +
    /// summands_i.
    ///
    /// # Arguments
    ///
    /// * `sink` - The IO sink to the receiver.
    /// * `stream` - The IO stream from the receiver.
    /// * `factors` - Provides the slopes for the linear functions.
    /// * `summands` - Provides the y-intercepts for the linear functions.
    async fn evaluate<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
        F: Field,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        factors: Vec<F>,
        summands: Vec<F>,
    ) -> Result<(), OLEError>;
}
