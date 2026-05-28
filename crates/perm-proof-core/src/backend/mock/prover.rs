//! Mock prover backend.

use std::marker::PhantomData;

use blake3::Hasher;
use mpz_fields::{ExtensionField, Field};

use super::{MockError, Preparation};
use crate::backend::{Backend, ProverBackend};

/// Mock prover backend.
pub struct MockProverBackend<W, E: Field> {
    /// Global key. Must match the verifier's.
    delta: E,

    /// Buffered product-wire keys emitted by
    /// [`product`](ProverBackend::product).
    prod_keys: Vec<E>,

    _phantom: PhantomData<W>,
}

impl<W, E: Field> MockProverBackend<W, E> {
    /// Build a new mock prover holding `delta`.
    pub fn new(delta: E) -> Self {
        Self {
            delta,
            prod_keys: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

impl<W: Field, E: ExtensionField<W>> Backend<W, E> for MockProverBackend<W, E> {
    type Error = MockError;
    type Preparation = Preparation<E>;
    type BackendProof = ();
}

impl<W: Field, E: ExtensionField<W>> ProverBackend<W, E> for MockProverBackend<W, E> {
    fn drain_preparation(&mut self) -> Result<Self::Preparation, Self::Error> {
        Ok(Preparation {
            prod_keys: std::mem::take(&mut self.prod_keys),
        })
    }

    fn prove(self, _transcript: &mut Hasher) -> Result<Self::BackendProof, Self::Error> {
        // Mock contributes no supplementary proof.
        Ok(())
    }

    fn product(&mut self, factor_values: &[E], factor_macs: &[E]) -> Result<(E, E), Self::Error> {
        assert_eq!(
            factor_values.len(),
            factor_macs.len(),
            "factor_values and factor_macs must be equal length"
        );

        // Cleartext product.
        let prod_value = factor_values.iter().copied().fold(E::one(), |a, b| a * b);

        // Any prod_mac satisfies the IT-MAC invariant.
        let prod_mac = E::rand(&mut rand::rng());

        let prod_key = prod_mac - self.delta * prod_value;

        self.prod_keys.push(prod_key);
        Ok((prod_value, prod_mac))
    }
}
