//! End-to-end tests for the Set membership protocol.

use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_two_shuffles::{
    set::{Prover, Verifier},
    strategy::{Char2Strategy, version::MultiplicativeStep},
    test_utils::{IDEAL_VOLE_POOL, commit_accesses, generate_set_witness, ideal_rvole_pair},
};
use mpz_vole_core::DerandVOLEReceiver;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use mpz_perm_proof_core::test_utils::build_ideal_perm_proof_pair as build_perm_proof_pair;

/// Element space — members are drawn from `0..ELEMENT_SPACE`.
const ELEMENT_SPACE: usize = 1 << 16;
/// Number of distinct members in the set.
const SET_SIZE: usize = 1024;
/// Lookups performed per session.
const TOTAL_LOOKUPS: usize = 512;
const FAN_IN: usize = 8;

/// Build the VOLE / perm-proof / version machinery and run setup →
/// lookups → teardown_prepare → teardown for one membership session.
fn run_session(
    rng: &mut ChaCha8Rng,
    delta: Gf2_64,
    prover_members: Vec<Vec<Gf2>>,
    verifier_members: Vec<Vec<Gf2>>,
    lookups: Vec<[Vec<Gf2>; 1]>,
) -> Result<(), mpz_two_shuffles::set::VerifierError> {
    let n_setup = verifier_members.len();

    // ---- VOLE ----
    let (user_rvole_s, user_rvole_r) = ideal_rvole_pair(rng, delta, IDEAL_VOLE_POOL);

    // ---- vole_zk perm-proof ----
    let (perm_prover, perm_verifier) =
        build_perm_proof_pair(rng, delta, n_setup + lookups.len(), FAN_IN);

    // ---- Build prover and verifier ----
    let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
        n_setup,
        MultiplicativeStep::new(lookups.len()).expect("supported size"),
        DerandVOLEReceiver::new(user_rvole_r),
        perm_prover,
    )
    .expect("prover new");

    let mut verifier = Verifier::<_, _, _, Char2Strategy<Gf2_64>>::new(
        n_setup,
        MultiplicativeStep::new(lookups.len()).expect("supported size"),
        user_rvole_s,
        perm_verifier,
    )
    .expect("verifier new");

    prover.alloc(lookups.len()).expect("prover alloc");
    verifier.alloc(lookups.len()).expect("verifier alloc");

    prover
        .setup(prover_members.into_iter().map(Into::into).collect())
        .expect("prover setup");
    verifier
        .setup(verifier_members.into_iter().map(Into::into).collect())
        .expect("verifier setup");

    // Commit lookups to a transcript.
    let (lookup_commits, transcript) = commit_accesses::<Gf2, Gf2_64, 1>(lookups, delta, rng);

    let mut p_transcript = transcript.clone();
    let mut v_transcript = transcript;
    // Prover and verifier transcript.
    for [(prover_elem, verifier_elem)] in lookup_commits {
        prover.lookup(prover_elem).expect("prover lookup");
        verifier.lookup(verifier_elem).expect("verifier lookup");
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
fn accepts_honest_membership() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();
    let witness = generate_set_witness(ELEMENT_SPACE, SET_SIZE, TOTAL_LOOKUPS, &mut rng);

    run_session(
        &mut rng,
        delta,
        witness.members.clone(),
        witness.members,
        witness.lookups,
    )
    .expect("honest case must accept");
}

/// Dishonest end-to-end.
#[test]
fn rejects_dishonest_set() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();
    let witness = generate_set_witness(ELEMENT_SPACE, SET_SIZE, TOTAL_LOOKUPS, &mut rng);

    let verifier_members = witness.members.clone();
    let mut prover_members = witness.members;

    // Pick a member that no lookup queries (fewer lookups than members,
    // so one is guaranteed) and flip a bit in it.
    let idx = prover_members
        .iter()
        .position(|m| !witness.lookups.iter().any(|[e]| e == m))
        .expect("some member is never looked up");
    prover_members[idx][0] = Gf2(!prover_members[idx][0].0);

    let err = run_session(
        &mut rng,
        delta,
        prover_members,
        verifier_members,
        witness.lookups,
    )
    .expect_err("dishonest case must reject");
    assert!(
        matches!(err, mpz_two_shuffles::set::VerifierError::PermProof(_)),
        "expected PermProof error, got {err:?}",
    );
}
