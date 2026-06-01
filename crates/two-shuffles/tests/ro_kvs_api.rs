//! End-to-end tests for the RO-KVS protocol public API.
//!
//! Drives the full `Prover` → `Verifier` lifecycle.

use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_two_shuffles::{
    ro_kvs::{Prover, Verifier},
    strategy::{Char2Strategy, version::MultiplicativeStep},
    test_utils::{IDEAL_VOLE_POOL, commit_accesses, generate_ro_kvs_witness, ideal_rvole_pair},
};
use mpz_vole_core::DerandVOLEReceiver;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use mpz_perm_proof_core::test_utils::build_ideal_perm_proof_pair as build_perm_proof_pair;

/// Key space — number of implicit keys `0..KEY_SPACE`, all populated.
const KEY_SPACE: usize = 1024;
/// Value bit-width.
const VALUE_BITS: usize = 16;
/// Lookups performed per session.
const TOTAL_LOOKUPS: usize = 512;
const FAN_IN: usize = 8;

/// Build the VOLE / perm-proof machinery and run setup → lookups →
/// teardown_prepare → teardown for one RO-KVS session.
fn run_session(
    rng: &mut ChaCha8Rng,
    delta: Gf2_64,
    prover_content: Vec<Vec<Gf2>>,
    verifier_content: Vec<Vec<Gf2>>,
    lookups: Vec<[Vec<Gf2>; 1]>,
) -> Result<(), mpz_two_shuffles::ro_kvs::VerifierError> {
    let n_setup = verifier_content.len();

    // ---- VOLE----
    let (user_rvole_s, user_rvole_r) = ideal_rvole_pair(rng, delta, IDEAL_VOLE_POOL);

    // ---- vole_zk perm-proof ----
    let (perm_prover, perm_verifier) =
        build_perm_proof_pair(rng, delta, n_setup + lookups.len(), FAN_IN);

    // ---- Build prover and verifier ----
    let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
        KEY_SPACE,
        VALUE_BITS,
        MultiplicativeStep::new(lookups.len()).expect("supported size"),
        DerandVOLEReceiver::new(user_rvole_r),
        perm_prover,
    )
    .expect("prover new");

    let mut verifier = Verifier::<_, _, _, Char2Strategy<Gf2_64>>::new(
        KEY_SPACE,
        VALUE_BITS,
        MultiplicativeStep::new(lookups.len()).expect("supported size"),
        user_rvole_s,
        perm_verifier,
    )
    .expect("verifier new");

    prover.alloc(n_setup, lookups.len()).expect("prover alloc");
    verifier
        .alloc(n_setup, lookups.len())
        .expect("verifier alloc");

    // Setup is public.
    prover.setup(prover_content).expect("prover setup");
    verifier.setup(verifier_content).expect("verifier setup");

    // Commit accesses to a transcript.
    let (lookup_commits, transcript) = commit_accesses::<Gf2, Gf2_64, 1>(lookups, delta, rng);
    // Prover and verifier transcript.
    let mut p_transcript = transcript.clone();
    let mut v_transcript = transcript;

    for [(prover_key, verifier_key)] in lookup_commits {
        prover.lookup(prover_key).expect("prover lookup");
        verifier.lookup(verifier_key).expect("verifier lookup");
    }

    let prepare = prover
        .teardown_prepare(&mut p_transcript)
        .expect("prover teardown_prepare");
    verifier
        .teardown_prepare(&mut v_transcript, prepare)
        .expect("verifier teardown_prepare");

    let msg = prover.teardown(&mut p_transcript).expect("prover teardown");
    verifier.teardown(msg, &mut v_transcript)
}

/// Honest end-to-end.
#[test]
fn accepts_honest_protocol() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();
    let witness = generate_ro_kvs_witness(KEY_SPACE, VALUE_BITS, TOTAL_LOOKUPS, &mut rng);

    run_session(
        &mut rng,
        delta,
        witness.content.clone(),
        witness.content,
        witness.lookups,
    )
    .expect("honest case must accept");
}

/// Dishonest end-to-end.
#[test]
fn rejects_dishonest_prover() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();
    let witness = generate_ro_kvs_witness(KEY_SPACE, VALUE_BITS, TOTAL_LOOKUPS, &mut rng);

    let verifier_content = witness.content.clone();
    let mut prover_content = witness.content;
    // Flip a bit in key 0's value — caught by the teardown read.
    prover_content[0][0] = Gf2(!prover_content[0][0].0);

    let err = run_session(
        &mut rng,
        delta,
        prover_content,
        verifier_content,
        witness.lookups,
    )
    .expect_err("dishonest case must reject");
    assert!(
        matches!(err, mpz_two_shuffles::ro_kvs::VerifierError::PermProof(_)),
        "expected PermProof error, got {err:?}",
    );
}
