//! End-to-end tests for the RAM protocol public API.
//!
//! Drives the full `ram::Prover` → `ram::Verifier` lifecycle.

use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_two_shuffles::{
    ProverWire, VerifierWire,
    ram::{Config, MultiplicativeClock, Prover, Verifier},
    set,
    strategy::{Char2Strategy, version::MultiplicativeStep},
    test_utils::{IDEAL_VOLE_POOL, commit_accesses, generate_ram_witness, ideal_rvole_pair},
};
use mpz_vole_core::{DerandVOLEReceiver, DerandVOLESender};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rangeset::set::RangeSet;

use mpz_perm_proof_core::test_utils::build_ideal_perm_proof_pair as build_perm_proof_pair;

/// Number of addressable memory cells.
const MEMORY_SIZE: usize = 1024;
/// Value bit-width (`2^VALUE_BITS` distinct values per cell).
const VALUE_BITS: usize = 16;
/// Memory accesses performed per session.
const TOTAL_ACCESSES: usize = 512;
const FAN_IN: usize = 8;

/// Build all VOLE / perm-proof / set machinery, run setup → accesses
/// → flush → teardown_prepare → teardown for one session, and return
/// the exported `(prover_state, verifier_state)` pair.
fn run_one_session(
    rng: &mut ChaCha8Rng,
    delta: Gf2_64,
    live_addrs: RangeSet<usize>,
    value_bits: usize,
    export_addrs: Option<RangeSet<usize>>,
    setup: SetupSource,
    access_tuples: Vec<[Vec<Gf2>; 3]>,
) -> Result<SessionState, mpz_two_shuffles::ram::VerifierError> {
    let t = access_tuples.len();
    let live_count = live_addrs.len();

    // ---- RAM RVOLE.
    let (ram_vole_s, ram_vole_r) = ideal_rvole_pair(rng, delta, IDEAL_VOLE_POOL);

    // ---- MulProver RVOLE.
    let (mul_rvole_s, mul_rvole_r) = ideal_rvole_pair(rng, delta, IDEAL_VOLE_POOL);

    // ---- MulProver VOLE.
    let (mul_vole_s, mul_vole_r) = ideal_rvole_pair(rng, delta, IDEAL_VOLE_POOL);

    // ---- set RVOLE.
    let (set_vole_s, set_vole_r) = ideal_rvole_pair(rng, delta, IDEAL_VOLE_POOL);

    // ---- vole_zk perm-proof for RAM.
    let (ram_perm_prover, ram_perm_verifier) =
        build_perm_proof_pair(rng, delta, live_count + t, FAN_IN);

    // ---- vole_zk perm-proof for set.
    let (set_perm_prover, set_perm_verifier) = build_perm_proof_pair(rng, delta, t + t, FAN_IN);

    // ---- Build set Prover/Verifier ----
    let prover_set = set::Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
        t,
        MultiplicativeStep::new(t).expect("supported version size"),
        DerandVOLEReceiver::new(set_vole_r),
        set_perm_prover,
    )
    .expect("set prover new");

    let verifier_set = set::Verifier::<_, _, _, Char2Strategy<Gf2_64>>::new(
        t,
        MultiplicativeStep::new(t).expect("supported version size"),
        set_vole_s,
        set_perm_verifier,
    )
    .expect("set verifier new");

    // ---- Build RAM Prover/Verifier ----
    let mut cfg_builder =
        Config::<Gf2_64, Char2Strategy<Gf2_64>>::builder(live_addrs, value_bits, t);
    if let Some(export) = export_addrs {
        cfg_builder = cfg_builder.export_addrs(export);
    }
    let config = cfg_builder.build().expect("ram config build");

    let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
        config.clone(),
        MultiplicativeClock::new(t).expect("supported clock size"),
        DerandVOLEReceiver::new(ram_vole_r),
        DerandVOLEReceiver::new(mul_vole_r),
        mul_rvole_r,
        ram_perm_prover,
        prover_set,
    )
    .expect("ram prover new");
    let mut verifier = Verifier::<_, _, _, Char2Strategy<Gf2_64>>::new(
        config,
        MultiplicativeClock::new(t).expect("supported clock size"),
        ram_vole_s,
        DerandVOLESender::new(mul_vole_s),
        mul_rvole_s,
        ram_perm_verifier,
        verifier_set,
    )
    .expect("ram verifier new");

    prover.alloc().expect("ram prover alloc");
    verifier.alloc().expect("ram verifier alloc");

    // ---- Setup ----
    match setup {
        SetupSource::Public(content) => {
            prover.setup(content.clone()).expect("ram prover setup");
            verifier.setup(content).expect("ram verifier setup");
        }
        SetupSource::PublicDishonest {
            verifier_truth,
            prover_content,
        } => {
            prover.setup(prover_content).expect("ram prover setup");
            verifier.setup(verifier_truth).expect("ram verifier setup");
        }
        SetupSource::Chained {
            prover_state,
            verifier_state,
        } => {
            prover
                .setup_with_wires(prover_state)
                .expect("ram prover setup_with_wires");
            verifier
                .setup_with_wires(verifier_state)
                .expect("ram verifier setup_with_wires");
        }
    }

    // Commit accesses to a transcript.
    let (access_commits, transcript) = commit_accesses(access_tuples, delta, rng);

    // Prover and verifier transcript.
    let mut p_transcript = transcript.clone();
    let mut v_transcript = transcript;

    for [
        (prover_op, verifier_op),
        (prover_addr, verifier_addr),
        (prover_w, verifier_w),
    ] in access_commits
    {
        prover
            .access(prover_op, prover_addr, prover_w)
            .expect("prover access (mux)");
        verifier
            .access(verifier_op, verifier_addr, verifier_w)
            .expect("verifier access (mux)");
    }

    let flush = prover.flush().expect("prover flush");
    verifier.flush(flush).expect("verifier flush");

    let prepare = prover
        .teardown_prepare(&mut p_transcript)
        .expect("prover teardown_prepare");
    verifier
        .teardown_prepare(&mut v_transcript, prepare)
        .expect("verifier teardown_prepare");

    let (msg, prover_state) = prover.teardown(&mut p_transcript).expect("prover teardown");
    let verifier_state = verifier.teardown(&mut v_transcript, msg)?;
    Ok((prover_state, verifier_state))
}

/// How a session seeds its memory at setup.
enum SetupSource {
    /// Public-constant setup. Both sides commit to the same content.
    Public(Vec<Vec<Gf2>>),
    /// Public-constant setup, but the prover commits to a tampered
    /// copy of the verifier's truth.
    PublicDishonest {
        verifier_truth: Vec<Vec<Gf2>>,
        prover_content: Vec<Vec<Gf2>>,
    },
    /// Chained from a previous session's exported state.
    Chained {
        prover_state: Vec<ProverWire<Gf2, Gf2_64>>,
        verifier_state: Vec<VerifierWire<Gf2_64>>,
    },
}

/// What a session returns when it tears down. Per-cell val wires
/// filtered to `config.export_addrs` and ordered by setup-time
/// insertion.
type SessionState = (Vec<ProverWire<Gf2, Gf2_64>>, Vec<VerifierWire<Gf2_64>>);

/// Honest end-to-end.
#[test]
fn accepts_honest_ram() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();
    let witness = generate_ram_witness(
        &RangeSet::from(0..MEMORY_SIZE),
        VALUE_BITS,
        TOTAL_ACCESSES,
        &mut rng,
    );

    run_one_session(
        &mut rng,
        delta,
        RangeSet::from(0..MEMORY_SIZE),
        VALUE_BITS,
        None,
        SetupSource::Public(witness.initial_memory),
        witness.accesses,
    )
    .expect("honest RAM must accept");
}

/// Dishonest end-to-end.
#[test]
fn rejects_dishonest_ram() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();
    let witness = generate_ram_witness(
        &RangeSet::from(0..MEMORY_SIZE),
        VALUE_BITS,
        TOTAL_ACCESSES,
        &mut rng,
    );

    let verifier_truth = witness.initial_memory.clone();
    let mut prover_content = witness.initial_memory;
    // Flip a bit in cell 0's value — the lie resolves locally on the
    // prover but the IT-MAC mismatch only surfaces at teardown.
    prover_content[0][0] = Gf2(!prover_content[0][0].0);

    let err = run_one_session(
        &mut rng,
        delta,
        RangeSet::from(0..MEMORY_SIZE),
        VALUE_BITS,
        None,
        SetupSource::PublicDishonest {
            verifier_truth,
            prover_content,
        },
        witness.accesses,
    )
    .map(|_| ())
    .expect_err("dishonest setup content must be rejected");
    assert!(
        matches!(err, mpz_two_shuffles::ram::VerifierError::PermProof(_)),
        "expected PermProof rejection, got {err:?}",
    );
}

/// Two chained sessions end-to-end. Session 1 runs over the full
/// memory but narrows its export to an arbitrary live region: two
/// disjoint, non-zero-based ranges, with holes below, between, and
/// above. Session 2 instantiates *only* that region (`live_addrs =
/// live_region`, so a smaller, sparse address space with a tighter
/// bound, fewer records, smaller perm proof) from session 1's exported
/// wires via `setup_with_wires`, and confines its accesses to it.
/// Integration check — both sessions must verify; the exported state
/// itself isn't re-checked here.
#[test]
fn accepts_chained_sessions() {
    let mut rng = ChaCha8Rng::seed_from_u64(0xC0DE_C0DE);
    let delta: Gf2_64 = rng.random();

    // Arbitrary live region carried from session 1 into session 2:
    // 16 cells across two disjoint, non-zero-based ranges.
    let live_region = RangeSet::from(vec![100..108usize, 500..508usize]);

    // ---- Session 1: full memory, export narrowed to `live_region`. ----
    let s1 = generate_ram_witness(
        &RangeSet::from(0..MEMORY_SIZE),
        VALUE_BITS,
        TOTAL_ACCESSES,
        &mut rng,
    );
    let (s1_prover_state, s1_verifier_state) = run_one_session(
        &mut rng,
        delta,
        RangeSet::from(0..MEMORY_SIZE),
        VALUE_BITS,
        Some(live_region.clone()),
        SetupSource::Public(s1.initial_memory),
        s1.accesses,
    )
    .expect("session 1 must accept");
    assert_eq!(s1_prover_state.len(), live_region.len());
    assert_eq!(s1_verifier_state.len(), live_region.len());

    // ---- Session 2: a RAM living on exactly `live_region`, chained
    // from session 1's exported wires; accesses confined to it. ----
    let s2 = generate_ram_witness(&live_region, VALUE_BITS, TOTAL_ACCESSES, &mut rng);
    run_one_session(
        &mut rng,
        delta,
        live_region,
        VALUE_BITS,
        None,
        SetupSource::Chained {
            prover_state: s1_prover_state,
            verifier_state: s1_verifier_state,
        },
        s2.accesses,
    )
    .expect("session 2 must accept");
}
