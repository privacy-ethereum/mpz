//! QuickSilver polynomial proof protocol.
//!
//! This crate implements the polynomial satisfiability proof from QuickSilver
//! (Yang et al., CCS'21), Section 3.2 / Figure 6.
//!
//! ## Soundness
//!
//! The protocol operates in the random oracle model. Error is bounded
//! by
//!
//! ```text
//! q / 2^256 + (d_max + 2) / |E|
//! ```
//!
//! where `d_max` is the maximum degree across the constraints and
//! `q` bounds the adversary's RO-query budget. Independent of the
//! number of evaluations. Both terms are negligible for any
//! cryptographically sized `E` and seed.

pub mod circuit;
#[cfg(any(test, feature = "fixture"))]
pub mod fixture;
pub mod prover;
pub mod verifier;

use std::fmt::Debug;

pub use mpz_fields::{ExtensionField, Field};
use serde::{Deserialize, Serialize};

use crate::circuit::{compile, BuildError, Circuit, CircuitBuilder, NodeId};

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

/// The proof message sent from prover to verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMessage<E> {
    /// Accumulated coefficient for each degree, excluding the highest
    /// (degrees 0 through d_max - 1).
    pub coefficients: Vec<E>,
}

/// Prover's side of a VOPE correlation.
#[derive(Debug, Clone)]
pub struct ProverVope<E> {
    /// One mask per coefficient (degrees 0 through d_max - 1).
    pub coeffs: Vec<E>,
}

/// Verifier's side of the VOPE correlation.
#[derive(Debug, Clone)]
pub struct VerifierVope<E> {
    /// Δ-weighted sum of the prover's masks.
    pub sum: E,
}

/// Identifier for a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConstraintId(pub(crate) usize);

/// A set of constraints.
#[derive(Clone)]
pub struct Constraints<E: Field> {
    pub(crate) circuits: Vec<Circuit<E>>,
}

impl<E: Field> Constraints<E> {
    /// Start building a constraint set.
    pub fn builder() -> ConstraintsBuilder<E> {
        ConstraintsBuilder {
            circuits: Vec::new(),
        }
    }
}

/// Builder for [`Constraints`].
pub struct ConstraintsBuilder<E: Field> {
    circuits: Vec<Circuit<E>>,
}

impl<E: Field> ConstraintsBuilder<E> {
    /// Add a constraint and return its [`ConstraintId`].
    ///
    /// The constraint is a `Context`-generic fn or closure with a
    /// fixed-size array parameter `[C::Wire; N]`; `N` is inferred from
    /// the signature. The closure must end with exactly one `assert_*`
    /// call, which becomes the constraint root.
    pub fn add<F, const N: usize>(&mut self, f: F) -> Result<ConstraintId, BuildError>
    where
        F: FnOnce(&mut CircuitBuilder<E>, [NodeId; N]) -> Result<(), BuildError>,
    {
        let circuit = compile(N, |cb, vars| {
            // `compile(N, …)` allocates exactly N input wires, so
            // `vars[i]` for `i < N` is always in bounds.
            f(cb, std::array::from_fn(|i| vars[i]))
        })?;
        let id = ConstraintId(self.circuits.len());
        self.circuits.push(circuit);
        Ok(id)
    }

    /// Like [`add`](Self::add), but with a runtime-sized variable count.
    ///
    /// Use when the number of input wires is only known at runtime.
    pub fn add_dynamic<F>(&mut self, num_vars: usize, f: F) -> Result<ConstraintId, BuildError>
    where
        F: FnOnce(&mut CircuitBuilder<E>, &[NodeId]) -> Result<(), BuildError>,
    {
        let circuit = compile(num_vars, f)?;
        let id = ConstraintId(self.circuits.len());
        self.circuits.push(circuit);
        Ok(id)
    }

    /// Freeze into a [`Constraints`] set.
    pub fn build(self) -> Constraints<E> {
        Constraints {
            circuits: self.circuits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuits_new::fixtures::{and_gate, linear_add};
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn random_gf64(rng: &mut impl Rng) -> Gf2_64 {
        Gf2_64(rng.random::<u64>())
    }

    fn auth_all<W: Field>(
        values: &[W],
        delta: Gf2_64,
        rng: &mut impl Rng,
    ) -> (Vec<Gf2_64>, Vec<Gf2_64>)
    where
        Gf2_64: ExtensionField<W>,
    {
        let mut macs = Vec::new();
        let mut keys = Vec::new();
        for &v in values {
            let mac = random_gf64(rng);
            let key = mac + Gf2_64::embed(v) * delta;
            macs.push(mac);
            keys.push(key);
        }
        (macs, keys)
    }

    fn mock_vope(
        count: usize,
        delta: Gf2_64,
        rng: &mut impl Rng,
    ) -> (ProverVope<Gf2_64>, VerifierVope<Gf2_64>) {
        let coeffs: Vec<Gf2_64> = (0..count).map(|_| random_gf64(rng)).collect();
        let mut sum = Gf2_64::ZERO;
        let mut delta_power = Gf2_64::ONE;
        for &c in &coeffs {
            sum = sum + c * delta_power;
            delta_power = delta_power * delta;
        }
        (ProverVope { coeffs }, VerifierVope { sum })
    }

    /// Build a Constraints set with a single AND-gate constraint.
    fn and_gate_constraints() -> (Constraints<Gf2_64>, ConstraintId) {
        let mut b = Constraints::<Gf2_64>::builder();
        let id = b.add(and_gate).unwrap();
        (b.build(), id)
    }

    /// Honest AND gate: w0=1, w1=1, w2=1 → 1·1+1=0 in F_2.
    #[test]
    fn test_and_gate_bool() {
        let mut rng = StdRng::seed_from_u64(42);
        let delta = random_gf64(&mut rng);
        let seed: [u8; 32] = rng.random();

        let values: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let (macs, vk) = auth_all(&values, delta, &mut rng);

        let (constraints, id) = and_gate_constraints();
        let mut p = prover::Prover::new(&constraints);
        let mut v = verifier::Verifier::new(delta, &constraints);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        p.accumulate(&[(id, macs.as_slice(), values.as_slice())], seed)
            .unwrap();
        let proof = p.finalize(&pv).unwrap();

        v.accumulate(&[(id, vk.as_slice())], seed).unwrap();
        assert!(
            v.finalize(&proof, &vv).is_ok(),
            "honest AND gate must verify"
        );
    }

    /// Dishonest AND gate: w0=1, w1=1, w2=0 → 1·1+0=1≠0.
    #[test]
    fn test_and_gate_dishonest() {
        let mut rng = StdRng::seed_from_u64(99);
        let delta = random_gf64(&mut rng);
        let seed: [u8; 32] = rng.random();

        let values: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ZERO];
        let (macs, vk) = auth_all(&values, delta, &mut rng);

        let (constraints, id) = and_gate_constraints();
        let mut p = prover::Prover::new(&constraints);
        let mut v = verifier::Verifier::new(delta, &constraints);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        p.accumulate(&[(id, macs.as_slice(), values.as_slice())], seed)
            .unwrap();
        let proof = p.finalize(&pv).unwrap();

        v.accumulate(&[(id, vk.as_slice())], seed).unwrap();
        assert!(
            v.finalize(&proof, &vv).is_err(),
            "dishonest must be rejected"
        );
    }

    /// Multiple evaluations batched with one seed.
    #[test]
    fn test_multiple_evaluations_batched() {
        let mut rng = StdRng::seed_from_u64(555);
        let delta = random_gf64(&mut rng);
        let seed: [u8; 32] = rng.random();

        let vals1: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let vals2: Vec<Gf2> = vec![Gf2::ZERO, Gf2::ONE, Gf2::ZERO];
        let (macs1, vk1) = auth_all(&vals1, delta, &mut rng);
        let (macs2, vk2) = auth_all(&vals2, delta, &mut rng);

        let (constraints, id) = and_gate_constraints();
        let mut p = prover::Prover::new(&constraints);
        let mut v = verifier::Verifier::new(delta, &constraints);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        p.accumulate(
            &[
                (id, macs1.as_slice(), vals1.as_slice()),
                (id, macs2.as_slice(), vals2.as_slice()),
            ],
            seed,
        )
        .unwrap();
        let proof = p.finalize(&pv).unwrap();

        v.accumulate(&[(id, vk1.as_slice()), (id, vk2.as_slice())], seed)
            .unwrap();
        assert!(v.finalize(&proof, &vv).is_ok(), "batched must verify");
    }

    /// Streaming: two separate accumulate calls with different seeds.
    #[test]
    fn test_streaming_batches() {
        let mut rng = StdRng::seed_from_u64(777);
        let delta = random_gf64(&mut rng);
        let seed_1: [u8; 32] = rng.random();
        let seed_2: [u8; 32] = rng.random();

        let vals1: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let vals2: Vec<Gf2> = vec![Gf2::ZERO, Gf2::ZERO, Gf2::ZERO];
        let (macs1, vk1) = auth_all(&vals1, delta, &mut rng);
        let (macs2, vk2) = auth_all(&vals2, delta, &mut rng);

        let (constraints, id) = and_gate_constraints();
        let mut p = prover::Prover::new(&constraints);
        let mut v = verifier::Verifier::new(delta, &constraints);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        p.accumulate(&[(id, macs1.as_slice(), vals1.as_slice())], seed_1)
            .unwrap();
        p.accumulate(&[(id, macs2.as_slice(), vals2.as_slice())], seed_2)
            .unwrap();
        let proof = p.finalize(&pv).unwrap();

        v.accumulate(&[(id, vk1.as_slice())], seed_1).unwrap();
        v.accumulate(&[(id, vk2.as_slice())], seed_2).unwrap();
        assert!(v.finalize(&proof, &vv).is_ok(), "streaming must verify");
    }

    /// Mixed degrees: one degree-2 and one degree-1 circuit.
    #[test]
    fn test_mixed_degrees() {
        let mut rng = StdRng::seed_from_u64(333);
        let delta = random_gf64(&mut rng);
        let seed: [u8; 32] = rng.random();

        let vals0: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let vals1: Vec<Gf2> = vec![Gf2::ZERO, Gf2::ZERO];
        let (macs0, vk0) = auth_all(&vals0, delta, &mut rng);
        let (macs1, vk1) = auth_all(&vals1, delta, &mut rng);

        let mut b = Constraints::<Gf2_64>::builder();
        let id_and = b.add(and_gate).unwrap(); // degree 2, 1 mult
        let id_linear = b.add(linear_add).unwrap(); // degree 1, no mults
        let constraints = b.build();

        let mut p = prover::Prover::new(&constraints);
        let mut v = verifier::Verifier::new(delta, &constraints);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        p.accumulate(
            &[
                (id_and, macs0.as_slice(), vals0.as_slice()),
                (id_linear, macs1.as_slice(), vals1.as_slice()),
            ],
            seed,
        )
        .unwrap();
        let proof = p.finalize(&pv).unwrap();

        v.accumulate(
            &[(id_and, vk0.as_slice()), (id_linear, vk1.as_slice())],
            seed,
        )
        .unwrap();
        assert!(v.finalize(&proof, &vv).is_ok(), "mixed degrees must verify");
    }

    /// End-to-end correctness test on all 12 step-circuit fixtures.
    ///
    /// For each circuit: pick random witness bits, set Y (var 0) so the
    /// constraint evaluates to zero, authenticate, then run the full
    /// prover/verifier flow.
    #[test]
    fn test_fixture_end_to_end() {
        use crate::fixture::add_step_constraints;

        let mut rng = StdRng::seed_from_u64(0xE2E);
        let delta = random_gf64(&mut rng);
        let seed: [u8; 32] = rng.random();

        let mut b = Constraints::<Gf2_64>::builder();
        let step = add_step_constraints(&mut b).unwrap();
        let constraints = b.build();

        let mut all_macs: Vec<Vec<Gf2_64>> = Vec::new();
        let mut all_vals: Vec<Vec<Gf2>> = Vec::new();
        let mut all_keys: Vec<Vec<Gf2_64>> = Vec::new();

        for circ in &constraints.circuits {
            let nv = circ.num_vars();

            // Random bits for all vars; Y (var 0) = ZERO initially.
            let mut vals: Vec<Gf2> = (0..nv).map(|_| Gf2(rng.random::<bool>())).collect();
            vals[0] = Gf2::ZERO;

            // Evaluate in cleartext to get the residual, then set Y so
            // the output is zero.
            let embedded: Vec<Gf2_64> = vals.iter().map(|&v| Gf2_64::embed(v)).collect();
            let residual = circ.evaluate(&embedded);
            vals[0] = if residual == Gf2_64::ONE {
                Gf2::ONE
            } else {
                Gf2::ZERO
            };

            // Authenticate.
            let (macs, keys) = auth_all(&vals, delta, &mut rng);
            all_macs.push(macs);
            all_vals.push(vals);
            all_keys.push(keys);
        }

        let p_evals: Vec<(ConstraintId, &[Gf2_64], &[Gf2])> = all_macs
            .iter()
            .zip(&all_vals)
            .enumerate()
            .map(|(i, (m, v))| (step.ids[i], m.as_slice(), v.as_slice()))
            .collect();
        let v_evals: Vec<(ConstraintId, &[Gf2_64])> = all_keys
            .iter()
            .enumerate()
            .map(|(i, k)| (step.ids[i], k.as_slice()))
            .collect();

        let mut p = prover::Prover::new(&constraints);
        let mut v = verifier::Verifier::new(delta, &constraints);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        p.accumulate(&p_evals, seed).unwrap();
        let proof = p.finalize(&pv).unwrap();

        v.accumulate(&v_evals, seed).unwrap();
        assert!(
            v.finalize(&proof, &vv).is_ok(),
            "all 12 fixture circuits must verify"
        );
    }
}
