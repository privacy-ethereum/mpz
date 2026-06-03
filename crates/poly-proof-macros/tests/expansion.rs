//! End-to-end test for the `#[poly_kernel]` macro pipeline.
//!
//! AST → IR correctness is pinned by the `interp` module's own unit
//! tests. This file exercises the *macro-specific* surface those
//! unit tests don't reach: the hand-emitted `ConstraintDef` bundle
//! (NUM_VARS / DEGREE consts, ProverKernel / VerifierKernel type
//! aliases, build_dag delegation) and the end-to-end prover↔verifier
//! agreement on what the macro-emitted kernels compute.
//!
//! One minimal constraint is enough: pattern coverage belongs to the
//! interp unit tests. Here we just need the simplest fn that produces
//! non-trivial kernel artifacts to thread through both sides of the
//! protocol.

use mpz_circuits_new::Context;
use mpz_fields::{ExtensionField, Field, gf2::Gf2, gf2_128::Gf2_128};
use mpz_poly_proof_core::{
    ConstraintsBuilder, ProverVope, VerifierVope, kernel::ConstraintDef, prover, verifier,
};
use mpz_poly_proof_macros::poly_kernel;
use rand::{Rng, SeedableRng, rngs::StdRng};

// Smallest meaningful constraint: `Y + X = 0`. Two vars, degree 1.
// Exercises the macro's emit of a `ProverKernel` impl that does one
// `add`, a `VerifierKernel` impl that does one Δ-shifted add, and a
// `ConstraintDef` bundle binding them together.
#[poly_kernel]
pub fn minimal<C, E>(ctx: &mut C, vars: [C::Wire; 2]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let out = ctx.add(vars[0], vars[1]);
    ctx.assert_const(out, E::zero())
}

#[test]
fn macro_bundle_verifies_end_to_end() {
    // Compile-time / const-value checks on the emitted ConstraintDef
    // bundle. If `extract_num_vars` or the degree derivation regress,
    // these fire.
    assert_eq!(<Minimal as ConstraintDef<Gf2_128, Gf2>>::NUM_VARS, 2);
    assert_eq!(<Minimal as ConstraintDef<Gf2_128, Gf2>>::DEGREE, 1);

    let mut rng = StdRng::seed_from_u64(0xC0DE);
    let delta = Gf2_128::new(rng.random::<u128>());
    let seed: [u8; 32] = rng.random();

    // Satisfying witness in GF(2): vars[0] + vars[1] = 0 iff they're
    // equal.
    let bit = Gf2(rng.random::<bool>());
    let values = vec![bit, bit];

    // Authenticate.
    let mac0 = Gf2_128::new(rng.random::<u128>());
    let mac1 = Gf2_128::new(rng.random::<u128>());
    let macs = vec![mac0, mac1];
    let keys = vec![
        mac0 + Gf2_128::embed(bit) * delta,
        mac1 + Gf2_128::embed(bit) * delta,
    ];

    // Build through the macro-emitted ConstraintDef: forces the
    // ProverKernel / VerifierKernel type aliases to resolve, the
    // `build_dag` impl method to compile, and the consts on the
    // bundle to round-trip into the builder's kernel entries.
    let mut b = ConstraintsBuilder::<Gf2_128, Gf2>::new();
    let id = b.add::<Minimal>().expect("ConstraintDef registration");
    let (pcs, vcs) = b.build();

    // Mock VOPE so we can call `finalize` honestly.
    let coeffs: Vec<Gf2_128> = (0..1).map(|_| Gf2_128::new(rng.random::<u128>())).collect();
    let mut sum = Gf2_128::ZERO;
    let mut dp = Gf2_128::ONE;
    for &c in &coeffs {
        sum = sum + c * dp;
        dp = dp * delta;
    }
    let pv = ProverVope { coeffs };
    let vv = VerifierVope { sum };

    // Prover: runs `<Minimal as ConstraintDef>::ProverKernel::accumulate`.
    let mut p = prover::Prover::new(&pcs).expect("prover new");
    p.accumulate(&[(id, macs.as_slice(), values.as_slice())], seed)
        .expect("prover accumulate");
    let proof = p.finalize(&pv).expect("prover finalize");

    // Verifier: runs `<Minimal as ConstraintDef>::VerifierKernel::evaluate`.
    // Honest proof must be accepted.
    let mut v = verifier::Verifier::new(delta, &vcs).expect("verifier new");
    v.accumulate(&[(id, keys.as_slice())])
        .expect("verifier accumulate");
    assert!(
        v.finalize(&proof, &vv, seed).is_ok(),
        "macro-emitted prover/verifier kernel pair must agree on an honest proof"
    );
}
