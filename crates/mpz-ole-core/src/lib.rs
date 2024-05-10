#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

//! Implementations of Oblivious Linear Evaluation (OLE).
//! Core logic of the protocols without I/O.

pub mod cope;
pub mod derand;
pub mod ideal;

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
/// An error for what can go wrong with OLE.
pub enum OLECoreError {
    #[error("{0}")]
    LengthMismatch(String),
}
