//! Mock verifier backend.

use std::{collections::VecDeque, marker::PhantomData};

use blake3::Hasher;
use mpz_fields::{ExtensionField, Field};

use super::{MockError, Preparation};
use crate::backend::{Backend, VerifierBackend};

/// Mock verifier backend.
pub struct MockVerifierBackend<W, E: Field> {
    /// Global key. Must match the prover's.
    delta: E,

    /// Product-wire keys loaded from a [`Preparation`], drained FIFO by
    /// [`product`](VerifierBackend::product).
    prod_keys: VecDeque<E>,

    _phantom: PhantomData<W>,
}

impl<W, E: Field> MockVerifierBackend<W, E> {
    /// Build a new mock verifier holding `delta`.
    pub fn new(delta: E) -> Self {
        Self {
            delta,
            prod_keys: VecDeque::new(),
            _phantom: PhantomData,
        }
    }
}

impl<W: Field, E: ExtensionField<W>> Backend<W, E> for MockVerifierBackend<W, E> {
    type Error = MockError;
    type Preparation = Preparation<E>;
    type BackendProof = ();
}

impl<W: Field, E: ExtensionField<W>> VerifierBackend<W, E> for MockVerifierBackend<W, E> {
    fn delta(&self) -> E {
        self.delta
    }

    fn load_preparation(&mut self, preparation: Self::Preparation) {
        self.prod_keys = preparation.prod_keys.into();
    }

    fn verify(
        self,
        _proof: Self::BackendProof,
        _transcript: &mut Hasher,
    ) -> Result<(), Self::Error> {
        // Mock contributes no supplementary check.
        Ok(())
    }

    fn product(&mut self, _factor_keys: &[E]) -> Result<E, Self::Error> {
        self.prod_keys
            .pop_front()
            .ok_or(MockError::ProdKeyUnderflow)
    }
}
