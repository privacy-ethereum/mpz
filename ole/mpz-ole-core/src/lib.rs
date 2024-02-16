#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

pub mod ole;
pub mod role;

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
/// An error
pub enum OLECoreError {
    #[error("{0}")]
    LengthMismatch(String),
}
