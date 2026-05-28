//! End-to-end tests for the permutation proof protocol public API.
//!
//! These tests drive the full `Prover` → `Verifier` lifecycle against
//! the non-cryptographic [`mock`](mpz_perm_proof_core::backend::mock)
//! backend.

use mpz_fields::{Field, gf2_128::Gf2_128};
use mpz_perm_proof_core::{
    Prover, Verifier,
    backend::mock::{MockError, mock_pair},
    test_utils::{Committed, commit_values},
    verifier::VerifyError,
};
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha8Rng;

/// Mode toggle for the end-to-end runners.
#[derive(Clone, Copy)]
enum Mode {
    /// Honest prover.
    Honest,
    /// Dishonest prover.
    Dishonest,
}

/// Drive the full two-round Prover → Verifier lifecycle over
/// `n = 100` tuples of width `L` and return the verifier's result.
fn run_end_to_end<const L: usize>(mode: Mode) -> Result<(), VerifyError<MockError>> {
    let mut rng = ChaCha8Rng::seed_from_u64(0xA1);
    let delta: Gf2_128 = rng.random();

    // Input tuples: `n` positions, each an `L`-wide tuple of random
    // field elements. `y` is a random permutation of `x`.
    let mut x_values: Vec<Vec<Gf2_128>> = (0..100)
        .map(|_| (0..L).map(|_| rng.random()).collect())
        .collect();
    // Fisher-Yates permutation on index vector; apply to build y.
    let mut perm_indices: Vec<usize> = (0..x_values.len()).collect();
    perm_indices.shuffle(&mut rng);
    let y_values: Vec<Vec<Gf2_128>> = perm_indices.iter().map(|&i| x_values[i].clone()).collect();

    // Commit both vectors as authenticated tuple-wires in a single
    // VOLE session.
    let Committed {
        macs: [x_macs, y_macs],
        keys: [x_keys, y_keys],
        transcript,
    } = commit_values([&x_values[..], &y_values[..]], delta, &mut rng);
    let mut tp = transcript.clone();
    let mut tv = transcript;

    if matches!(mode, Mode::Dishonest) {
        // Tamper AFTER authentication.
        x_values[0][0] = x_values[0][0] + Gf2_128::one();
    }

    let (pb, vb) = mock_pair::<Gf2_128, Gf2_128>(delta);
    let mut prover = Prover::new(pb);
    let mut verifier = Verifier::new(vb);

    // --- Round 1: prover -> verifier ---
    let preparation = prover
        .prepare(&mut tp, (&x_values, &x_macs), (&y_values, &y_macs))
        .expect("prover prepare must succeed");
    verifier
        .prepare(&mut tv, &x_keys, &y_keys, preparation)
        .expect("verifier prepare must succeed");

    // --- Round 2: prover -> verifier ---
    let proof = prover
        .prove(&mut tp)
        .expect("prover prove must succeed");
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
    assert!(
        matches!(err, VerifyError::ZeroCheckFailed),
        "expected ZeroCheckFailed, got {err:?}"
    );
}
