//! Message types for different OLE protocols.

use enum_try_as_inner::EnumTryAsInner;
use mpz_share_conversion_core::Field;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, EnumTryAsInner, Serialize, Deserialize)]
#[derive_err(Debug)]
/// A message type for ROLEe protocols.
pub enum ROLEeMessage<T, F: Field> {
    /// Messages of the random OT protocol.
    RandomOTMessage(T),
    /// Random field elements sent by the provider.
    ///
    /// These are u_i and e_k.
    RandomProviderMsg(Vec<F>, Vec<F>),
    /// Random field elements sent by the evaluator.
    ///
    /// These are d_k.
    RandomEvaluatorMsg(Vec<F>),
}

impl<T, F: Field> From<ROLEeMessageError<T, F>> for std::io::Error {
    fn from(err: ROLEeMessageError<T, F>) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
    }
}

#[derive(Debug, Clone, EnumTryAsInner, Serialize, Deserialize)]
#[derive_err(Debug)]
/// A message type for OLEe protocols.
pub enum OLEeMessage<T, F: Field> {
    /// Messages of the underlying ROLEe protocol.
    ROLEeMessage(T),
    /// Field elements sent by the provider.
    ProviderDerand(Vec<F>),
    /// Field elements sent by the evaluator.
    EvaluatorDerand(Vec<F>),
}

impl<T, F: Field> From<OLEeMessageError<T, F>> for std::io::Error {
    fn from(err: OLEeMessageError<T, F>) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
    }
}
