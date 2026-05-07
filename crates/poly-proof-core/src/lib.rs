//! Core logic for the QuickSilver polynomial proof protocol.
//!
//! This crate implements the polynomial satisfiability proof from QuickSilver
//! (Yang et al., CCS'21), Section 3.2 / Figure 6.
//!
//! # Setting
//!
//! The protocol is generic over two type parameters:
//!
//! - **`E: mpz_fields::Field`** — the extension field used for MACs, keys, and
//!   Delta (e.g., GF(2^64) via [`mpz_fields::gf2_64::Gf2_64`]).
//!
//! - **`W: Field`** with `E: ExtensionField<W>` — the witness value type, a
//!   subfield element that embeds into `E` (e.g.,
//!   [`mpz_fields::gf2::Gf2`] for F_2, or `Gf2_64` itself for the full-field
//!   case once the corresponding `ExtensionField` impl exists).
//!
//! ## Soundness budget
//!
//! Soundness of the proof rests on Schwartz-Zippel over `E`: for a batch of
//! `T` evaluations of constraints with maximum degree `d_max`, a cheating
//! prover succeeds with probability at most `(T + d_max) / |E|`.
//!
//! [`prover::Prover`] and [`verifier::Verifier`] therefore cap the cumulative
//! batch size across all [`accumulate`](prover::Prover::accumulate) calls.
//! The cap is chosen so that the resulting error stays at most `2⁻ˢˢᵖ`, where
//! the statistical security parameter (SSP) defaults to [`DEFAULT_SSP`] bits.
//! Callers can raise the SSP via
//! [`Prover::with_statistical_security_bits`](prover::Prover::with_statistical_security_bits)
//! or
//! [`Verifier::with_statistical_security_bits`](verifier::Verifier::with_statistical_security_bits).
//!
//! Once the cap is reached, `accumulate` returns a `SoundnessBudget` error;
//! callers must either start a fresh session or widen `E`.

pub mod circuit;
#[cfg(any(test, feature = "fixture"))]
pub mod fixture;
pub mod prover;
pub(crate) mod soundness;
pub mod verifier;

use std::fmt::Debug;

pub use mpz_fields::{ExtensionField, Field};
use serde::{Deserialize, Serialize};

/// Default — and minimum — statistical security parameter (SSP), in bits.
pub const DEFAULT_SSP: u32 = 40;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::CircuitBuilder;
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use rand::{Rng, SeedableRng, rngs::StdRng};

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

    /// Build the AND gate circuit: w0·w1 + w2 = 0.
    fn and_gate_circuit() -> crate::circuit::Circuit<Gf2_64> {
        let mut cb = CircuitBuilder::new();
        let w0 = cb.var(0);
        let w1 = cb.var(1);
        let w2 = cb.var(2);
        let prod = cb.mul(w0, w1);
        let out = cb.add(prod, w2);
        cb.build(out)
    }

    /// Honest AND gate: w0=1, w1=1, w2=1 → 1·1+1=0 in F_2.
    #[test]
    fn test_and_gate_bool() {
        let mut rng = StdRng::seed_from_u64(42);
        let delta = random_gf64(&mut rng);
        let chi = random_gf64(&mut rng);

        let circuit = and_gate_circuit();
        let values: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let (macs, vk) = auth_all(&values, delta, &mut rng);

        let d_max = circuit.degree();
        let (pv, vv) = mock_vope(d_max, delta, &mut rng);

        let mut p = prover::Prover::new(vec![circuit.clone()]);
        p.accumulate(&[(0, macs.as_slice(), values.as_slice())], chi)
            .unwrap();
        let proof = p.finalize(&pv).unwrap();

        let mut v = verifier::Verifier::new(delta, vec![circuit]);
        v.accumulate(&[(0, vk.as_slice())], chi).unwrap();
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
        let chi = random_gf64(&mut rng);

        let circuit = and_gate_circuit();
        let values: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ZERO];
        let (macs, vk) = auth_all(&values, delta, &mut rng);

        let d_max = circuit.degree();
        let (pv, vv) = mock_vope(d_max, delta, &mut rng);

        let mut p = prover::Prover::new(vec![circuit.clone()]);
        p.accumulate(&[(0, macs.as_slice(), values.as_slice())], chi)
            .unwrap();
        let proof = p.finalize(&pv).unwrap();

        let mut v = verifier::Verifier::new(delta, vec![circuit]);
        v.accumulate(&[(0, vk.as_slice())], chi).unwrap();
        assert!(
            v.finalize(&proof, &vv).is_err(),
            "dishonest must be rejected"
        );
    }

    /// Multiple evaluations batched with one chi.
    #[test]
    fn test_multiple_evaluations_batched() {
        let mut rng = StdRng::seed_from_u64(555);
        let delta = random_gf64(&mut rng);
        let chi = random_gf64(&mut rng);

        let circuit = and_gate_circuit();
        let vals1: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let vals2: Vec<Gf2> = vec![Gf2::ZERO, Gf2::ONE, Gf2::ZERO];
        let (macs1, vk1) = auth_all(&vals1, delta, &mut rng);
        let (macs2, vk2) = auth_all(&vals2, delta, &mut rng);

        let d_max = circuit.degree();
        let (pv, vv) = mock_vope(d_max, delta, &mut rng);

        let mut p = prover::Prover::new(vec![circuit.clone()]);
        p.accumulate(
            &[
                (0, macs1.as_slice(), vals1.as_slice()),
                (0, macs2.as_slice(), vals2.as_slice()),
            ],
            chi,
        )
        .unwrap();
        let proof = p.finalize(&pv).unwrap();

        let mut v = verifier::Verifier::new(delta, vec![circuit]);
        v.accumulate(&[(0, vk1.as_slice()), (0, vk2.as_slice())], chi)
            .unwrap();
        assert!(v.finalize(&proof, &vv).is_ok(), "batched must verify");
    }

    /// Streaming: two separate accumulate calls with different chi values.
    #[test]
    fn test_streaming_batches() {
        let mut rng = StdRng::seed_from_u64(777);
        let delta = random_gf64(&mut rng);
        let chi_1 = random_gf64(&mut rng);
        let chi_2 = random_gf64(&mut rng);

        let circuit = and_gate_circuit();
        let vals1: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let vals2: Vec<Gf2> = vec![Gf2::ZERO, Gf2::ZERO, Gf2::ZERO];
        let (macs1, vk1) = auth_all(&vals1, delta, &mut rng);
        let (macs2, vk2) = auth_all(&vals2, delta, &mut rng);

        let d_max = circuit.degree();
        let (pv, vv) = mock_vope(d_max, delta, &mut rng);

        let mut p = prover::Prover::new(vec![circuit.clone()]);
        p.accumulate(&[(0, macs1.as_slice(), vals1.as_slice())], chi_1)
            .unwrap();
        p.accumulate(&[(0, macs2.as_slice(), vals2.as_slice())], chi_2)
            .unwrap();
        let proof = p.finalize(&pv).unwrap();

        let mut v = verifier::Verifier::new(delta, vec![circuit]);
        v.accumulate(&[(0, vk1.as_slice())], chi_1).unwrap();
        v.accumulate(&[(0, vk2.as_slice())], chi_2).unwrap();
        assert!(v.finalize(&proof, &vv).is_ok(), "streaming must verify");
    }

    /// Mixed degrees: one degree-2 and one degree-1 circuit.
    #[test]
    fn test_mixed_degrees() {
        let mut rng = StdRng::seed_from_u64(333);
        let delta = random_gf64(&mut rng);
        let chi = random_gf64(&mut rng);

        // Circuit 0 (degree 2): w0·w1 + w2 = 0
        let circ0 = and_gate_circuit();
        // Circuit 1 (degree 1): w0 + w1 = 0
        let mut cb = CircuitBuilder::new();
        let a = cb.var(0);
        let b = cb.var(1);
        let out = cb.add(a, b);
        let circ1 = cb.build(out);

        let vals0: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let vals1: Vec<Gf2> = vec![Gf2::ZERO, Gf2::ZERO];
        let (macs0, vk0) = auth_all(&vals0, delta, &mut rng);
        let (macs1, vk1) = auth_all(&vals1, delta, &mut rng);

        let circuits = vec![circ0, circ1];
        let d_max = circuits.iter().map(|c| c.degree()).max().unwrap();
        let (pv, vv) = mock_vope(d_max, delta, &mut rng);

        let mut p = prover::Prover::new(circuits.clone());
        p.accumulate(
            &[
                (0, macs0.as_slice(), vals0.as_slice()),
                (1, macs1.as_slice(), vals1.as_slice()),
            ],
            chi,
        )
        .unwrap();
        let proof = p.finalize(&pv).unwrap();

        let mut v = verifier::Verifier::new(delta, circuits);
        v.accumulate(&[(0, vk0.as_slice()), (1, vk1.as_slice())], chi)
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
        use crate::fixture::step_circuit_polynomials;

        let mut rng = StdRng::seed_from_u64(0xE2E);
        let delta = random_gf64(&mut rng);
        let chi = random_gf64(&mut rng);

        let (circuits, _counts) = step_circuit_polynomials::<Gf2_64>();
        let d_max = circuits.iter().map(|c| c.degree()).max().unwrap();
        let (pv, vv) = mock_vope(d_max, delta, &mut rng);

        let mut all_macs: Vec<Vec<Gf2_64>> = Vec::new();
        let mut all_vals: Vec<Vec<Gf2>> = Vec::new();
        let mut all_keys: Vec<Vec<Gf2_64>> = Vec::new();

        for circ in &circuits {
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

        let p_evals: Vec<(usize, &[Gf2_64], &[Gf2])> = all_macs
            .iter()
            .zip(&all_vals)
            .enumerate()
            .map(|(i, (m, v))| (i, m.as_slice(), v.as_slice()))
            .collect();
        let v_evals: Vec<(usize, &[Gf2_64])> = all_keys
            .iter()
            .enumerate()
            .map(|(i, k)| (i, k.as_slice()))
            .collect();

        let mut p = prover::Prover::new(circuits.clone());
        p.accumulate(&p_evals, chi).unwrap();
        let proof = p.finalize(&pv).unwrap();

        let mut v = verifier::Verifier::new(delta, circuits);
        v.accumulate(&v_evals, chi).unwrap();
        assert!(
            v.finalize(&proof, &vv).is_ok(),
            "all 12 fixture circuits must verify"
        );
    }
}
