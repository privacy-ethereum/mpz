//! End-to-end tests for the permutation-proof public API against the
//! production [`vole_zk`](mpz_perm_proof_core::backend::vole_zk)
//! backend, with the ideal VOLE functionalities.

use mpz_fields::{Field, gf2_128::Gf2_128};
use mpz_perm_proof_core::{
    Prover, Verifier,
    backend::vole_zk::{VoleZkProverBackend, VoleZkVerifierBackend, VoleZkVerifierError},
    test_utils::{
        Committed, commit_values, ideal_perm_proof_rvole_pair, ideal_perm_proof_rvope_pair,
    },
    verifier::VerifyError,
};
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha8Rng;

/// Mode toggle for the end-to-end runners.
#[derive(Clone, Copy)]
enum Mode {
    /// Honest prover.
    Honest,
    /// Dishonest prover: tampers an input AFTER authentication, so the
    /// MACs/keys still bind to the original value and the IT-MAC
    /// invariant on that wire is broken.
    Dishonest,
}

/// Fan-in of the product tree the vole-zk backend uses.
const FAN_IN: usize = 8;

/// Permutation size.
const N: usize = 100;

/// Drive the full two-round Prover → Verifier lifecycle over `N` tuples
/// of width `L` and return the verifier's result.
fn run_end_to_end<const L: usize>(mode: Mode) -> Result<(), VerifyError<VoleZkVerifierError>> {
    let mut rng = ChaCha8Rng::seed_from_u64(0xA1);
    let delta: Gf2_128 = rng.random();

    // Inputs: `x` is random; `y` is `x` permuted via Fisher-Yates.
    let mut x_values: Vec<Vec<Gf2_128>> = (0..N)
        .map(|_| (0..L).map(|_| rng.random()).collect())
        .collect();
    let mut perm_indices: Vec<usize> = (0..x_values.len()).collect();
    perm_indices.shuffle(&mut rng);
    let y_values: Vec<Vec<Gf2_128>> = perm_indices.iter().map(|&i| x_values[i].clone()).collect();

    // Authenticate both vectors via a single ideal VOLE session. Returns
    // prover-side MACs, verifier-side keys, and a transcript bound to the
    // on-wire commit. Both parties start their Fiat-Shamir transcripts
    // from this committed state.
    let Committed {
        macs: [x_macs, y_macs],
        keys: [x_keys, y_keys],
        transcript,
    } = commit_values([&x_values[..], &y_values[..]], delta, &mut rng);

    // Ideal RVOLE / RVOPE correlations, allocated + flushed for one run.
    let (rvole_s, rvole_r) = ideal_perm_proof_rvole_pair::<Gf2_128>(&mut rng, delta, N, FAN_IN);
    let (rvope_s, rvope_r) = ideal_perm_proof_rvope_pair::<Gf2_128>(&mut rng, delta, FAN_IN);

    // Construct the production vole-zk backends and wrap them in the
    // `Prover` / `Verifier` state machine.
    let prover_backend =
        VoleZkProverBackend::<Gf2_128, Gf2_128, _, _>::new(FAN_IN, rvole_r, rvope_r)
            .expect("vole-zk prover backend");
    let verifier_backend =
        VoleZkVerifierBackend::<Gf2_128, Gf2_128, _, _>::new(FAN_IN, delta, rvole_s, rvope_s)
            .expect("vole-zk verifier backend");
    let mut prover = Prover::new(prover_backend);
    let mut verifier = Verifier::new(verifier_backend);
    prover.alloc(N).expect("prover alloc");
    verifier.alloc(N).expect("verifier alloc");

    // Dishonest case: tamper AFTER authentication is locked in. The
    // MACs/keys still bind to the original value, so the verifier
    // rejects.
    if matches!(mode, Mode::Dishonest) {
        x_values[0][0] = x_values[0][0] + Gf2_128::one();
    }

    // The transcript is cloned so each party advances its own copy from the
    // committed state.
    let mut tp = transcript.clone();
    let mut tv = transcript;

    let preparation = prover
        .prepare(&mut tp, (&x_values, &x_macs), (&y_values, &y_macs))
        .expect("prover prepare");
    verifier
        .prepare(&mut tv, &x_keys, &y_keys, preparation)
        .expect("verifier prepare");

    let proof = prover.prove(&mut tp).expect("prover prove");
    verifier.verify(proof, &mut tv)
}

/// Honest end-to-end with scalar inputs (`L = 1`).
#[test]
fn accepts_honest_permutation_scalar_n100() {
    run_end_to_end::<1>(Mode::Honest).expect("honest case must accept");
}

/// Dishonest end-to-end with scalar inputs.
#[test]
fn rejects_non_permutation_scalar_n100() {
    let err =
        run_end_to_end::<1>(Mode::Dishonest).expect_err("dishonest scalar case must be rejected");
    // Wrapper-level zero check (prover's opened MAC vs verifier's diff
    // key) fires before the backend's QS verify gets a chance, so this
    // is the expected reject path for tampered-after-auth inputs.
    assert!(
        matches!(err, VerifyError::ZeroCheckFailed),
        "expected ZeroCheckFailed, got {err:?}"
    );
}

/// Honest end-to-end with 3-tuple inputs.
#[test]
fn accepts_honest_permutation_tuples3_n100() {
    run_end_to_end::<3>(Mode::Honest).expect("honest tuple case must accept");
}

/// Dishonest end-to-end with 3-tuple inputs.
#[test]
fn rejects_non_permutation_tuples3_n100() {
    let err =
        run_end_to_end::<3>(Mode::Dishonest).expect_err("dishonest tuple case must be rejected");
    // Wrapper-level zero check (prover's opened MAC vs verifier's diff
    // key) fires before the backend's QS verify gets a chance, so this
    // is the expected reject path for tampered-after-auth inputs.
    assert!(
        matches!(err, VerifyError::ZeroCheckFailed),
        "expected ZeroCheckFailed, got {err:?}"
    );
}
