#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

//! This crate provides implementations of different Oblivious Linear Evaluation with Errors (OLEe)
//! flavors. It provides the core logic of the protocols without I/O.

pub mod ole;
pub mod role;

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
/// An error for what can go wrong with OLE
pub enum OLECoreError {
    #[error("{0}")]
    LengthMismatch(String),
}
