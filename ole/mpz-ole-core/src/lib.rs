pub mod role;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OLECoreError {
    #[error("{0}")]
    LengthMismatch(String),
}
