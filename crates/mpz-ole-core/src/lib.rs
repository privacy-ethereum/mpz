//! Implementations of Oblivious Linear Function Evaluation (OLE).
//!
//! Core logic of the protocol without I/O.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

pub mod ideal;

mod core;
mod receiver;
mod sender;

pub use receiver::OLEReceiver;
pub use sender::OLESender;

#[derive(Debug, thiserror::Error)]
pub enum OLEError {
    #[error("The number of field elements is incorrect. Expected a multiple of {0}, but got {1}")]
    ExpectedMultipleOf(usize, usize),
    #[error("Not enough prepared OLEs available. Requested {0}, but only {1} are available")]
    InsufficientOLEs(usize, usize),
    #[error("Number of adjustments has to be equal. Got {0} and {1}")]
    UnequalAdjustments(usize, usize),
}
