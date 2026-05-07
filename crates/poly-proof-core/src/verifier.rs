//! Verifier-side logic for the QuickSilver polynomial proof.

use rand_chacha::{
    ChaCha12Rng,
    rand_core::{RngCore, SeedableRng},
};
use zerocopy::IntoBytes;

use crate::{
    Field, ProofMessage, VerifierVope,
    circuit::{Circuit, CircuitNode},
};

/// Verifier for the QuickSilver polynomial proof.
///
/// Constructed with the same constraint circuits as the prover.
/// Accumulates the same evaluations in the same order, then checks
/// the proof.
#[derive(Clone)]
pub struct Verifier<E: Field> {
    /// The constraint circuits, indexed by `poly_id`.
    circuits: Vec<Circuit<E>>,
    /// Maximum polynomial degree across all circuits.
    d_max: usize,
    /// Pre-computed powers of Δ: `delta_pow[i]` = Δⁱ.
    delta_pow: Vec<E>,
    /// Running scalar accumulator (full polynomial evaluated at Δ).
    accumulator: E,
}

impl<E: Field> Verifier<E> {
    /// Create a new verifier from the MAC key `delta` and constraint
    /// `circuits`.
    pub fn new(delta: E, circuits: Vec<Circuit<E>>) -> Self {
        let d_max = circuits.iter().map(|c| c.degree()).max().unwrap_or(0);
        let mut delta_pow = vec![E::one(); d_max + 1];
        for i in 1..=d_max {
            delta_pow[i] = delta_pow[i - 1] * delta;
        }
        Self {
            circuits,
            d_max,
            delta_pow,
            accumulator: E::zero(),
        }
    }

    /// Accumulate a batch of polynomial evaluations under a `seed`.
    ///
    /// Each evaluation is a `(poly_id, keys)` pair: the circuit to
    /// evaluate and one verifier key per variable.
    ///
    /// `seed` must be bound to a Fiat-Shamir transcript covering all
    /// witness commitments preceding the call.
    pub fn accumulate(
        &mut self,
        evaluations: &[(usize, &[E])],
        seed: [u8; 32],
    ) -> Result<(), VerifierError>
    where
        E: IntoBytes + zerocopy::FromBytes,
    {
        let mut chis = vec![<E as Field>::zero(); evaluations.len()];
        let mut rng = ChaCha12Rng::from_seed(seed);
        rng.fill_bytes(chis.as_mut_slice().as_mut_bytes());

        for (&(poly_id, keys), &chi) in evaluations.iter().zip(chis.iter()) {
            let b = self.evaluate_circuit(poly_id, keys)?;
            self.accumulator = self.accumulator + b * chi;
        }
        Ok(())
    }

    /// Check the proof against the accumulated evaluations.
    pub fn finalize(
        self,
        proof: &ProofMessage<E>,
        vope: &VerifierVope<E>,
    ) -> Result<(), VerifierError> {
        if proof.coefficients.len() != self.d_max {
            return Err(ErrorRepr::ProofLength {
                expected: self.d_max,
                actual: proof.coefficients.len(),
            }
            .into());
        }

        let w = self.accumulator + vope.sum;

        let mut rhs = E::zero();
        for h in 0..self.d_max {
            rhs = rhs + proof.coefficients[h] * self.delta_pow[h];
        }

        if w != rhs {
            return Err(ErrorRepr::Invalid.into());
        }

        Ok(())
    }

    /// Walk the circuit bottom-up, computing a single scalar per node
    /// (substituting verifier keys for variables, with Δ-power alignment
    /// for Add nodes of different degrees).
    fn evaluate_circuit(&self, poly_id: usize, keys: &[E]) -> Result<E, VerifierError> {
        if poly_id >= self.circuits.len() {
            return Err(ErrorRepr::UnknownPolyId {
                poly_id,
                count: self.circuits.len(),
            }
            .into());
        }
        let circuit = &self.circuits[poly_id];
        let n_vars = circuit.num_vars();
        if keys.len() != n_vars {
            return Err(ErrorRepr::KeyCount {
                poly_id,
                expected: n_vars,
                actual: keys.len(),
            }
            .into());
        }
        let mut node_vals: Vec<E> = Vec::with_capacity(circuit.nodes.len());

        for node in &circuit.nodes {
            let val = match *node {
                CircuitNode::Var(idx) => keys[idx],
                CircuitNode::Const(c) => c,
                CircuitNode::Mul(a, b) => node_vals[a] * node_vals[b],
                // The lower-degree operand is multiplied by Δ^shift to
                // align with the higher-degree one before adding.
                CircuitNode::Add(a, b) => {
                    let da = circuit.node_degrees[a];
                    let db = circuit.node_degrees[b];
                    let d = da.max(db);
                    let shift_a = d - da;
                    let shift_b = d - db;
                    let va = if shift_a == 0 {
                        node_vals[a]
                    } else {
                        node_vals[a] * self.delta_pow[shift_a]
                    };
                    let vb = if shift_b == 0 {
                        node_vals[b]
                    } else {
                        node_vals[b] * self.delta_pow[shift_b]
                    };
                    va + vb
                }
                CircuitNode::Neg(a) => -node_vals[a],
            };
            node_vals.push(val);
        }

        // Degree-align the output with d_max.
        let shift = self.d_max - circuit.degree();
        Ok(if shift == 0 {
            node_vals[circuit.output]
        } else {
            node_vals[circuit.output] * self.delta_pow[shift]
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
    #[error("unknown poly_id: {poly_id} (only {count} circuits registered)")]
    UnknownPolyId { poly_id: usize, count: usize },
    #[error("wrong number of keys for poly_id {poly_id}: expected {expected}, got {actual}")]
    KeyCount {
        poly_id: usize,
        expected: usize,
        actual: usize,
    },
}
