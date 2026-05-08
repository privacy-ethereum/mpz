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
    /// On entry, `transcript` is guaranteed to have absorbed
    /// `factor_values` and `factor_macs`. On return, the
    /// implementation must have absorbed any on-wire bytes it
    /// emitted during the call into `transcript`.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Shared session transcript.
    /// * `factor_values` - Cleartext values of the factor wires.
    /// * `factor_macs` - Per-position MACs matching `factor_values`.
    fn product(
        &mut self,
        transcript: &mut Hasher,
        factor_values: &[E],
        factor_macs: &[E],
    ) -> Result<(E, E), Self::Error>;

    /// Drain the buffered preparation DTO.
    fn drain_preparation(&mut self) -> Result<Self::Preparation, Self::Error>;

    /// Produce the backend-specific proof.
    fn prove(self) -> Result<Self::BackendProof, Self::Error>;
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
    /// On entry, `transcript` is guaranteed to have absorbed
    /// `factor_keys`. On return, the implementation must have
    /// absorbed any on-wire bytes it received during the call into
    /// `transcript`.
    ///
    /// # Arguments
    ///
    /// * `transcript` - Shared session transcript.
    /// * `factor_keys` - Per-position keys for the factor wires.
    fn product(&mut self, transcript: &mut Hasher, factor_keys: &[E]) -> Result<E, Self::Error>;

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
    fn verify(self, proof: Self::BackendProof) -> Result<(), Self::Error>;
}
