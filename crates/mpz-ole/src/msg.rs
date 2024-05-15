//! Message types for different OLE protocols.

use enum_try_as_inner::EnumTryAsInner;
use mpz_fields::Field;
use mpz_ole_core::msg::{BatchAdjust, MaskedInputs};
use serde::{Deserialize, Serialize};

/// A message type for OLE.
#[derive(Debug, EnumTryAsInner, Serialize, Deserialize)]
#[derive_err(Debug)]
pub enum OLEMessage<F: Field> {
    /// Correlations sent by the sender to the receiver.
    Masked(MaskedInputs<F>),
    /// Adjustments sent to each other for share adjustment.
    Adjust(BatchAdjust<F>),
}

impl<F: Field> From<OLEMessageError<F>> for std::io::Error {
    fn from(err: OLEMessageError<F>) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
    }
}
