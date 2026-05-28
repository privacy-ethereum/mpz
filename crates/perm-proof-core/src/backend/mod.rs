//! Backend traits for the permutation proof.

use blake3::Hasher;
use mpz_fields::{ExtensionField, Field};

#[cfg(any(test, feature = "test-utils"))]
pub mod mock;
pub mod vole_zk;

/// Types shared by a paired prover/verifier backend.
pub trait Backend<W: Field, E: ExtensionField<W>> {
    /// Error type produced by fallible backend operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Preparation DTO: data the verifier can start processing the
    /// moment the prover's `product` calls are done.
    type Preparation;

    /// Backend-specific supplementary proof.
    type BackendProof;
}

/// Prover backend for the permutation proof.
pub trait ProverBackend<W: Field, E: ExtensionField<W>>: Backend<W, E> + Sized {
    /// Allocate capacity for proving a permutation of size `n`.
    ///
    /// May be called multiple times: each call allocates additional
    /// capacity on top of prior calls.
    ///
    /// # Arguments
    ///
    /// * `n` - Size of the permutation to prove.
    fn alloc(&mut self, _n: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Authenticated product of `n` factors. Returns the
    /// `(value, MAC)` of the product wire.

    ///
    /// # Arguments
    ///
    /// * `factor_values` - Cleartext values of the factor wires.
    /// * `factor_macs` - Per-position MACs matching `factor_values`.
    fn product(&mut self, factor_values: &[E], factor_macs: &[E]) -> Result<(E, E), Self::Error>;

    /// Drain the buffered preparation DTO.
    fn drain_preparation(&mut self) -> Result<Self::Preparation, Self::Error>;

    /// Produce the backend-specific proof.
    ///
    /// # Arguments
    ///
    /// * `transcript` - the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`product`](Self::product) before this call —
    /// otherwise the protocol's soundness guarantee no longer holds.
    fn prove(self, transcript: &mut Hasher) -> Result<Self::BackendProof, Self::Error>;
}

/// Verifier backend for the permutation proof.
pub trait VerifierBackend<W: Field, E: ExtensionField<W>>: Backend<W, E> + Sized {
    /// Verifier's global key `Δ`.
    fn delta(&self) -> E;

    /// Allocate capacity for verifying a permutation of size `n`.
    ///
    /// May be called multiple times: each call allocates additional
    /// capacity on top of prior calls.
    ///
    /// # Arguments
    ///
    /// * `n` - Size of the permutation to verify.
    fn alloc(&mut self, _n: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Consumes the keys for `n` authenticated factors and returns
    /// the key for the product wire.
    ///
    /// Any on-wire bytes the backend processes during the call are
    /// absorbed into the backend's own internal transcript, not into
    /// the caller's external transcript. [`verify`](Self::verify)
    /// folds that internal transcript into the caller's external
    /// transcript before drawing any challenges. Mirrors the
    /// prover-side [`ProverBackend::product`].
    ///
    /// # Arguments
    ///
    /// * `factor_keys` - Per-position keys for the factor wires.
    fn product(&mut self, factor_keys: &[E]) -> Result<E, Self::Error>;

    /// Install the preparation DTO.
    ///
    /// # Arguments
    ///
    /// * `preparation` - The prover-emitted preparation DTO.
    fn load_preparation(&mut self, preparation: Self::Preparation);

    /// Verify the backend-specific proof.

    ///
    /// # Arguments
    ///
    /// * `proof` - The prover-emitted backend proof DTO.
    /// * `transcript` - the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`product`](Self::product) before this call —
    /// otherwise the protocol's soundness guarantee no longer holds.
    fn verify(self, proof: Self::BackendProof, transcript: &mut Hasher) -> Result<(), Self::Error>;
}
