//! Mock backend.

use mpz_fields::Field;
use serde::{Deserialize, Serialize};

pub mod prover;
pub mod verifier;

pub use prover::MockProverBackend;
pub use verifier::MockVerifierBackend;

/// Preparation DTO for the mock backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preparation<E: Field> {
    /// Verifier-side IT-MAC keys for product wires, declared by the
    /// prover (legal here because the mock prover knows `Δ`), one per
    /// `product` call, in emission order.
    pub prod_keys: Vec<E>,
}

/// Error produced by the mock prover / verifier.
#[derive(Debug, thiserror::Error)]
pub enum MockError {
    /// The verifier ran out of buffered prod_keys.
    #[error("ran out of prod_keys at product")]
    ProdKeyUnderflow,
}

/// Build a paired mock prover and verifier sharing `delta`.
pub fn mock_pair<W, E: Field>(delta: E) -> (MockProverBackend<W, E>, MockVerifierBackend<W, E>) {
    (
        MockProverBackend::new(delta),
        MockVerifierBackend::new(delta),
    )
}
