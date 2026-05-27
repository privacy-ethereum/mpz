//! Verifier for the QuickSilver polynomial proof protocol.

use rand_chacha::{
    ChaCha12Rng,
    rand_core::{RngCore, SeedableRng},
};
use zerocopy::IntoBytes;

use crate::{
    ConstraintId, Field, ProofMessage, VerifierConstraint, VerifierConstraints, VerifierVope,
};

/// Verifier for the QuickSilver polynomial proof protocol.
#[derive(Clone)]
pub struct Verifier<E: Field> {
    /// Per-constraint-id body.
    bodies: Vec<VerifierConstraint<E>>,
    /// Maximum polynomial degree across all constraints.
    d_max: usize,
    /// Pre-computed powers of Δ: `delta_pow[i]` = Δⁱ.
    delta_pow: Vec<E>,
    /// Buffered per-evaluation scalars.
    pending_b: Vec<E>,
}

impl<E: Field> Verifier<E> {
    /// Create a new verifier from the global `delta` key and a
    /// constraint set.
    pub fn new(delta: E, constraints: &VerifierConstraints<E>) -> Self {
        let bodies = constraints.bodies.clone();
        let d_max = bodies
            .iter()
            .map(|b| match b {
                VerifierConstraint::Kernel(k) => k.degree,
                VerifierConstraint::Circuit(c) => c.degree(),
            })
            .max()
            .unwrap_or(0);
        let mut delta_pow = vec![E::one(); d_max + 1];
        for i in 1..=d_max {
            delta_pow[i] = delta_pow[i - 1] * delta;
        }
        Self {
            bodies,
            d_max,
            delta_pow,
            pending_b: Vec::new(),
        }
    }

    /// Evaluate a batch of polynomial constraints and buffer the
    /// resulting scalars for later folding.
    ///
    /// Each evaluation is a `(id, keys)` pair: the constraint to
    /// evaluate and one verifier key per variable.
    pub fn accumulate(
        &mut self,
        evaluations: &[(ConstraintId, &[E])],
    ) -> Result<(), VerifierError> {
        self.pending_b.reserve(evaluations.len());
        for &(id, keys) in evaluations {
            let b = self.evaluate(id, keys)?;
            self.pending_b.push(b);
        }
        Ok(())
    }

    /// Verifies the proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - prover's proof message.
    /// * `vope` - verifier's VOPE share.
    /// * `seed` - Fiat-Shamir seed for the χ weights. Must be derived from a
    ///   transcript that has already absorbed the keys of all calls to
    ///   [`Verifier::accumulate`]. The protocol's soundness depends on this
    ///   binding.
    pub fn finalize(
        self,
        proof: &ProofMessage<E>,
        vope: &VerifierVope<E>,
        seed: [u8; 32],
    ) -> Result<(), VerifierError>
    where
        E: IntoBytes + zerocopy::FromBytes,
    {
        if proof.coefficients.len() != self.d_max {
            return Err(ErrorRepr::ProofLength {
                expected: self.d_max,
                actual: proof.coefficients.len(),
            }
            .into());
        }

        // Draw chi values from the seed-fed PRG, one per buffered b.
        let n = self.pending_b.len();
        let mut chis = vec![<E as Field>::zero(); n];
        let mut rng = ChaCha12Rng::from_seed(seed);
        rng.fill_bytes(chis.as_mut_slice().as_mut_bytes());

        // Fold buffered b's into the accumulator.
        let mut accumulator = <E as Field>::zero();
        for (b, chi) in self.pending_b.iter().zip(chis.iter()) {
            accumulator = accumulator + *b * *chi;
        }

        let w = accumulator + vope.sum;

        let mut rhs = <E as Field>::zero();
        for h in 0..self.d_max {
            rhs = rhs + proof.coefficients[h] * self.delta_pow[h];
        }

        if w != rhs {
            return Err(ErrorRepr::Invalid.into());
        }

        Ok(())
    }

    /// Evaluate constraint `id` at the verifier's keys.
    fn evaluate(&self, id: ConstraintId, keys: &[E]) -> Result<E, VerifierError> {
        if id.0 >= self.bodies.len() {
            return Err(ErrorRepr::UnknownConstraint {
                id,
                count: self.bodies.len(),
            }
            .into());
        }

        let (val, degree) = match &self.bodies[id.0] {
            VerifierConstraint::Kernel(k) => {
                if keys.len() != k.num_vars {
                    return Err(ErrorRepr::KeyCount {
                        id,
                        expected: k.num_vars,
                        actual: keys.len(),
                    }
                    .into());
                }
                ((k.evaluate)(keys, &self.delta_pow), k.degree)
            }
            VerifierConstraint::Circuit(circuit) => {
                if keys.len() != circuit.num_vars() {
                    return Err(ErrorRepr::KeyCount {
                        id,
                        expected: circuit.num_vars(),
                        actual: keys.len(),
                    }
                    .into());
                }
                (circuit.evaluate(keys, &self.delta_pow), circuit.degree())
            }
        };

        // Degree-align the own-degree value with d_max.
        let shift = self.d_max - degree;
        Ok(if shift == 0 {
            val
        } else {
            val * self.delta_pow[shift]
        })
    }

    /// Number of VOPEs the caller must prepare for
    /// [`finalize`](Verifier::finalize).
    pub fn required_vopes(&self) -> usize {
        // d+1 coefficients, minus the highest-degree one (not sent) = d.
        self.d_max
    }
}

/// Verifier error.
#[derive(Debug, thiserror::Error)]
#[error("verifier error: {0}")]
pub struct VerifierError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("proof verification failed: check equation does not hold")]
    Invalid,
    #[error("incorrect proof length: expected {expected}, got {actual}")]
    ProofLength { expected: usize, actual: usize },
    #[error("unknown constraint id {id:?} (only {count} constraints registered)")]
    UnknownConstraint { id: ConstraintId, count: usize },
    #[error("wrong number of keys for constraint {id:?}: expected {expected}, got {actual}")]
    KeyCount {
        id: ConstraintId,
        expected: usize,
        actual: usize,
    },
}
