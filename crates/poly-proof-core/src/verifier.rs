//! Verifier-side logic for the QuickSilver polynomial proof.

use crate::{
    DEFAULT_SSP, Field, ProofMessage, VerifierVope,
    circuit::{Circuit, CircuitNode},
    soundness::max_evaluations,
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
    /// Maximum cumulative number of evaluations permitted under the
    /// configured SSP.
    max_evaluations: u64,
    /// Number of evaluations accumulated so far across all `accumulate`
    /// calls.
    eval_count: u64,
}

impl<E: Field> Verifier<E> {
    /// Create a new verifier from the MAC key `delta` and constraint
    /// `circuits`, enforcing the default statistical security parameter of
    /// [`DEFAULT_SSP`] bits.
    pub fn new(delta: E, circuits: Vec<Circuit<E>>) -> Self {
        Self::with_statistical_security_bits(delta, circuits, DEFAULT_SSP)
    }

    /// Create a new verifier that enforces `ssp` bits of statistical security.
    ///
    /// Panics if `ssp < `[`DEFAULT_SSP`].
    pub fn with_statistical_security_bits(delta: E, circuits: Vec<Circuit<E>>, ssp: u32) -> Self {
        assert!(
            ssp >= DEFAULT_SSP,
            "ssp must be at least DEFAULT_SSP ({DEFAULT_SSP}); got {ssp}"
        );
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
            max_evaluations: max_evaluations(E::BIT_SIZE, ssp, d_max),
            eval_count: 0,
        }
    }

    /// Accumulate a batch of polynomial evaluations with batching challenge
    /// `chi`.
    ///
    /// Each evaluation is a `(poly_id, keys)` pair: the circuit to
    /// evaluate and one verifier key per variable.
    pub fn accumulate(
        &mut self,
        evaluations: &[(usize, &[E])],
        chi: E,
    ) -> Result<(), VerifierError> {
        let new_count = self.eval_count.saturating_add(evaluations.len() as u64);
        if new_count > self.max_evaluations {
            return Err(ErrorRepr::SoundnessBudget {
                max: self.max_evaluations,
                attempted: new_count,
            }
            .into());
        }
        let mut chi_power = E::one();
        for &(poly_id, keys) in evaluations {
            let b = self.evaluate_circuit(poly_id, keys)?;
            self.accumulator = self.accumulator + b * chi_power;
            chi_power = chi_power * chi;
        }
        self.eval_count = new_count;
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

    /// Override the SSP-derived cap on cumulative `accumulate` count.
    /// Test-only.
    #[cfg(test)]
    pub(crate) fn set_max_evaluations(&mut self, n: u64) {
        self.max_evaluations = n;
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
    #[error(
        "SSP budget exceeded: accumulating this batch would make T = {attempted}, but the configured statistical security parameter permits at most {max} evaluations"
    )]
    SoundnessBudget { max: u64, attempted: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::CircuitBuilder;
    use mpz_fields::gf2_64::Gf2_64;

    fn and_gate_circuit() -> Circuit<Gf2_64> {
        let mut cb = CircuitBuilder::new();
        let w0 = cb.var(0);
        let w1 = cb.var(1);
        let w2 = cb.var(2);
        let prod = cb.mul(w0, w1);
        let out = cb.add(prod, w2);
        cb.build(out)
    }

    #[test]
    fn with_statistical_security_bits_rejects_ssp_below_default() {
        let result = std::panic::catch_unwind(|| {
            Verifier::with_statistical_security_bits(
                Gf2_64(0),
                vec![and_gate_circuit()],
                DEFAULT_SSP - 1,
            )
        });
        assert!(result.is_err());
    }

    #[test]
    fn accumulate_rejects_batch_past_budget() {
        let mut v = Verifier::new(Gf2_64(0), vec![and_gate_circuit()]);
        v.set_max_evaluations(1);

        let keys = vec![Gf2_64(0); 3];
        let chi = Gf2_64(1);

        v.accumulate(&[(0, keys.as_slice())], chi)
            .expect("first batch fits in budget");

        let err = v
            .accumulate(&[(0, keys.as_slice())], chi)
            .expect_err("second batch must exceed budget");
        assert!(matches!(
            err.0,
            ErrorRepr::SoundnessBudget {
                max: 1,
                attempted: 2
            }
        ));
    }
}
