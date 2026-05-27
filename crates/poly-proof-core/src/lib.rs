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
pub mod kernel;
#[cfg(any(test, feature = "fixture"))]
pub mod gen_kernels {
    //! Lifter-generated kernels.
    //!
    //! Built by `build.rs` at compile time via `mpz-poly-proof-lifter`.
    //! `fixture::*` references these through `ConstraintDef` impls,
    //! and `test_fixture_end_to_end` exercises them through the full
    //! prover↔verifier protocol.
    include!(concat!(env!("OUT_DIR"), "/gen_kernels.rs"));
}
pub mod prover;
pub mod verifier;

#[cfg(test)]
mod test_utils;

use std::fmt::Debug;

pub use mpz_fields::{ExtensionField, Field};
use serde::{Deserialize, Serialize};

mod constraint;
pub use constraint::{
    ConstraintId, ConstraintsBuilder, ProverConstraints, ProverKernelEntry, VerifierConstraints,
    VerifierKernelEntry,
};
pub(crate) use constraint::{ProverConstraint, VerifierConstraint};

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
    use crate::{
        fixture::{
            AccMux, AddrBaseMux, AddrIndexMux, CarryChain, CarryGenerate, FpMux, MulBitExtraction,
            MulForce, PcMux, SpMux, WriteBack, WriteBackBit0, add_step_constraints,
        },
        kernel::ConstraintDef,
        test_utils::EvalCtx,
    };
    use mpz_circuits_new::fixtures::{
        acc_mux, addr_base_mux, addr_index_mux, and_gate, carry_chain, carry_generate, fp_mux,
        linear_add, mul_bit_extraction, mul_force, pc_mux, sp_mux, write_back, write_back_bit0,
    };
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use crate::test_utils::{and_gate_constraints, auth_all, mock_vope, random_gf64};

    /// End-to-end correctness test.
    #[test]
    fn test_fixture_end_to_end() {
        let mut rng = StdRng::seed_from_u64(0xE2E);
        let delta = random_gf64(&mut rng);
        let seed: [u8; 32] = rng.random();

        // Register all constraints: the 12 step fixtures as kernels,
        // then the same 12 upstream fns again as runtime DAG bodies, so
        // the protocol exercises the circuit-walk path alongside the
        // kernels.
        let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
        let step = add_step_constraints(&mut b).unwrap();

        macro_rules! add_dyn {
            ($C:ty, $f:path) => {
                b.add_dynamic(<$C as ConstraintDef<Gf2_64, Gf2>>::NUM_VARS, |cb, v| {
                    $f(cb, v.try_into().unwrap())
                })
                .unwrap()
            };
        }
        let dyn_ids: Vec<ConstraintId> = vec![
            add_dyn!(CarryGenerate, carry_generate),
            add_dyn!(CarryChain, carry_chain),
            add_dyn!(WriteBack, write_back),
            add_dyn!(WriteBackBit0, write_back_bit0),
            add_dyn!(AddrBaseMux, addr_base_mux),
            add_dyn!(AddrIndexMux, addr_index_mux),
            add_dyn!(MulBitExtraction, mul_bit_extraction),
            add_dyn!(MulForce, mul_force),
            add_dyn!(AccMux, acc_mux),
            add_dyn!(PcMux, pc_mux),
            add_dyn!(SpMux, sp_mux),
            add_dyn!(FpMux, fp_mux),
        ];

        let (pcs, vcs) = b.build();

        let mut all_macs: Vec<Vec<Gf2_64>> = Vec::new();
        let mut all_vals: Vec<Vec<Gf2>> = Vec::new();
        let mut all_keys: Vec<Vec<Gf2_64>> = Vec::new();

        // Solve a satisfying witness for one constraint: run its fn over
        // cleartext candidates (var0 = 0) to get the residual, then set
        // var0 to cancel it. Returns the authenticated (macs, vals, keys).
        type ConstraintRun = dyn Fn(&mut EvalCtx<Gf2_64>, &[Gf2_64]) -> Result<(), ()>;
        let mut solve =
            |num_vars: usize, run: &ConstraintRun| -> (Vec<Gf2_64>, Vec<Gf2>, Vec<Gf2_64>) {
                let mut vals: Vec<Gf2> = (0..num_vars).map(|_| Gf2(rng.random::<bool>())).collect();
                vals[0] = Gf2::ZERO;
                let embedded: Vec<Gf2_64> = vals.iter().map(|&v| Gf2_64::embed(v)).collect();
                let mut ctx = EvalCtx::new();
                run(&mut ctx, &embedded).expect("cleartext eval must succeed");
                let residual = ctx.into_output();
                vals[0] = if residual == Gf2_64::ONE {
                    Gf2::ONE
                } else {
                    Gf2::ZERO
                };
                let (macs, keys) = auth_all(&vals, delta, &mut rng);
                (macs, vals, keys)
            };

        // Order must match `add_step_constraints` (→ `step.ids`).
        macro_rules! solve {
            ($C:ty, $f:path) => {{
                let (m, v, k) = solve(<$C as ConstraintDef<Gf2_64, Gf2>>::NUM_VARS, &|c, vs| {
                    $f(c, vs.try_into().unwrap())
                });
                all_macs.push(m);
                all_vals.push(v);
                all_keys.push(k);
            }};
        }
        solve!(CarryGenerate, carry_generate);
        solve!(CarryChain, carry_chain);
        solve!(WriteBack, write_back);
        solve!(WriteBackBit0, write_back_bit0);
        solve!(AddrBaseMux, addr_base_mux);
        solve!(AddrIndexMux, addr_index_mux);
        solve!(MulBitExtraction, mul_bit_extraction);
        solve!(MulForce, mul_force);
        solve!(AccMux, acc_mux);
        solve!(PcMux, pc_mux);
        solve!(SpMux, sp_mux);
        solve!(FpMux, fp_mux);

        // Feed each solved witness to both its kernel id and its dynamic
        // twin, so both bodies are evaluated in the protocol.
        let p_evals: Vec<(ConstraintId, &[Gf2_64], &[Gf2])> = (0..all_macs.len())
            .flat_map(|i| {
                let (m, v) = (all_macs[i].as_slice(), all_vals[i].as_slice());
                [(step.ids[i], m, v), (dyn_ids[i], m, v)]
            })
            .collect();
        let v_evals: Vec<(ConstraintId, &[Gf2_64])> = (0..all_keys.len())
            .flat_map(|i| {
                let k = all_keys[i].as_slice();
                [(step.ids[i], k), (dyn_ids[i], k)]
            })
            .collect();

        let mut p = prover::Prover::new(&pcs);
        let mut v = verifier::Verifier::new(delta, &vcs);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        p.accumulate(&p_evals, seed).unwrap();
        let proof = p.finalize(&pv).unwrap();

        v.accumulate(&v_evals).unwrap();
        assert!(
            v.finalize(&proof, &vv, seed).is_ok(),
            "all 12 fixtures (kernel + DAG bodies) must verify"
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

        let (pcs, vcs, id) = and_gate_constraints();
        let mut p = prover::Prover::new(&pcs);
        let mut v = verifier::Verifier::new(delta, &vcs);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        p.accumulate(&[(id, macs.as_slice(), values.as_slice())], seed)
            .unwrap();
        let proof = p.finalize(&pv).unwrap();

        v.accumulate(&[(id, vk.as_slice())]).unwrap();
        assert!(
            v.finalize(&proof, &vv, seed).is_err(),
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

        let (pcs, vcs, id) = and_gate_constraints();
        let mut p = prover::Prover::new(&pcs);
        let mut v = verifier::Verifier::new(delta, &vcs);
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

        v.accumulate(&[(id, vk1.as_slice()), (id, vk2.as_slice())])
            .unwrap();
        assert!(v.finalize(&proof, &vv, seed).is_ok(), "batched must verify");
    }

    /// Verifier-side streaming: multiple `accumulate` calls share a
    /// single end-of-protocol seed at `finalize`.
    #[test]
    fn test_streaming_batches() {
        let mut rng = StdRng::seed_from_u64(777);
        let delta = random_gf64(&mut rng);
        let seed: [u8; 32] = rng.random();

        let vals1: Vec<Gf2> = vec![Gf2::ONE, Gf2::ONE, Gf2::ONE];
        let vals2: Vec<Gf2> = vec![Gf2::ZERO, Gf2::ZERO, Gf2::ZERO];
        let (macs1, vk1) = auth_all(&vals1, delta, &mut rng);
        let (macs2, vk2) = auth_all(&vals2, delta, &mut rng);

        let (pcs, vcs, id) = and_gate_constraints();
        let mut p = prover::Prover::new(&pcs);
        let mut v = verifier::Verifier::new(delta, &vcs);
        let (pv, vv) = mock_vope(p.required_vopes(), delta, &mut rng);

        // Prover: one batch combining both evaluations, single seed.
        p.accumulate(
            &[
                (id, macs1.as_slice(), vals1.as_slice()),
                (id, macs2.as_slice(), vals2.as_slice()),
            ],
            seed,
        )
        .unwrap();
        let proof = p.finalize(&pv).unwrap();

        // Verifier: streams across multiple accumulate calls in the
        // same order, then folds at finalize with the same seed.
        v.accumulate(&[(id, vk1.as_slice())]).unwrap();
        v.accumulate(&[(id, vk2.as_slice())]).unwrap();
        assert!(
            v.finalize(&proof, &vv, seed).is_ok(),
            "verifier-side streaming must verify"
        );
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

        let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
        let id_and = b
            .add_dynamic(3, |cb, vars| {
                let arr: [_; 3] = vars.try_into().unwrap();
                and_gate(cb, arr)
            })
            .unwrap(); // degree 2, 1 mult
        let id_linear = b
            .add_dynamic(2, |cb, vars| {
                let arr: [_; 2] = vars.try_into().unwrap();
                linear_add(cb, arr)
            })
            .unwrap(); // degree 1, no mults
        let (pcs, vcs) = b.build();

        let mut p = prover::Prover::new(&pcs);
        let mut v = verifier::Verifier::new(delta, &vcs);
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

        v.accumulate(&[(id_and, vk0.as_slice()), (id_linear, vk1.as_slice())])
            .unwrap();
        assert!(
            v.finalize(&proof, &vv, seed).is_ok(),
            "mixed degrees must verify"
        );
    }
}
