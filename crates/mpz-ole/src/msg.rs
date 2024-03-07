//! Message types for different OLE protocols.

use enum_try_as_inner::EnumTryAsInner;
use mpz_fields::Field;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, EnumTryAsInner, Serialize, Deserialize)]
#[derive_err(Debug)]
/// A message type for ROLEe protocols.
pub enum ROLEeMessage<F: Field> {
    /// Random field elements sent by the provider.
    ///
    /// These are u_i and e_k.
    RandomProviderMsg(Vec<F>, Vec<F>),
    /// Random field elements sent by the evaluator.
    ///
    /// These are d_k.
    RandomEvaluatorMsg(Vec<F>),
}

impl<F: Field> From<ROLEeMessageError<F>> for std::io::Error {
    fn from(err: ROLEeMessageError<F>) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
    }
}

#[derive(Debug, Clone, EnumTryAsInner, Serialize, Deserialize)]
#[derive_err(Debug)]
/// A message type for OLEe protocols.
pub enum OLEeMessage<F: Field> {
    /// Field elements sent by the provider.
    ProviderDerand(Vec<F>),
    /// Field elements sent by the evaluator.
    EvaluatorDerand(Vec<F>),
}

impl<F: Field> From<OLEeMessageError<F>> for std::io::Error {
    fn from(err: OLEeMessageError<F>) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
    }
}
