//! End-to-end benchmark for the Set membership protocol using ideal VOLE.
//!
//! Run with:
//!
//!     cargo bench --bench set

use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_perm_proof_core::{
    backend::vole_zk::{Preparation, Proof, VoleZkProverBackend, VoleZkVerifierBackend},
    test_utils::build_ideal_perm_proof_pair,
};
use mpz_two_shuffles::{
    Bundle, ProverWire, VerifierWire,
    set::{self, Prover, Verifier},
    strategy::{
        Char2Strategy,
        version::{MultiplicativeStep, VersionStep},
    },
    test_utils::{generate_set_witness, ideal_rvole_pair},
};
use mpz_vole_core::{
    DerandVOLEReceiver,
    ideal::{
        rvole::{IdealRVOLEReceiver, IdealRVOLESender},
        rvope::IdealRVOPESender,
    },
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

// ---------------------------------------------------------------------------
// Bench config
// ---------------------------------------------------------------------------

/// Number of distinct members in the set.
const SET_SIZE: usize = 100_000;
/// Element space — members are drawn from `0..ELEMENT_SPACE`.
const ELEMENT_SPACE: usize = 1 << 17;
/// Number of lookups.
const N_LOOKUPS: usize = 100_000;
/// Perm-proof fan-in.
const FAN_IN: usize = 8;

// Concrete prover/verifier types — spelled out so `BenchState` can
// name them.
type ProverBackend = VoleZkProverBackend<
    Gf2_64,
    Gf2_64,
    IdealRVOLEReceiver<Gf2_64, Gf2_64>,
    mpz_vole_core::ideal::rvope::IdealRVOPEReceiver<Gf2_64>,
>;
type VerifierBackend =
    VoleZkVerifierBackend<Gf2_64, Gf2_64, IdealRVOLESender<Gf2_64>, IdealRVOPESender<Gf2_64>>;

type SetProver =
    Prover<IdealRVOLEReceiver<Gf2, Gf2_64>, Gf2_64, ProverBackend, Char2Strategy<Gf2_64>>;
type SetVerifier =
    Verifier<IdealRVOLESender<Gf2_64>, Gf2_64, VerifierBackend, Char2Strategy<Gf2_64>>;

/// Everything the timed region needs. Built once per sample; the
/// measured routine consumes it.
struct BenchState {
    prover: SetProver,
    verifier: SetVerifier,
    delta: Gf2_64,
    members: Vec<Bundle<Gf2>>,
    lookups: Vec<Vec<Gf2>>,
    /// Caller-supplied Fiat-Shamir transcripts.
    p_transcript: blake3::Hasher,
    v_transcript: blake3::Hasher,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Offline phase: generate the witness, correlations, and backends,
/// construct prover and verifier, allocate VOLE / perm-proof state.
/// Everything here is excluded from the measured time.
fn offline_setup(n_setup: usize, num_lookups: usize) -> BenchState {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();

    // ---- Witness: distinct members + in-set lookup trace.
    let witness = generate_set_witness(ELEMENT_SPACE, n_setup, num_lookups, &mut rng);
    let members: Vec<Bundle<Gf2>> = witness.members.into_iter().map(Bundle::new).collect();
    let lookups: Vec<Vec<Gf2>> = witness.lookups.into_iter().map(|[e]| e).collect();

    // ---- Version steps (sized to the worst-case per-element lookup count).
    let prover_step = MultiplicativeStep::new(num_lookups).expect("supported size");
    let verifier_step = MultiplicativeStep::new(num_lookups).expect("supported size");
    let l_ver = VersionStep::<Gf2>::len(&prover_step);

    // ---- User-facing input-gate VOLE.
    let (user_rvole_s, user_rvole_r) =
        ideal_rvole_pair(&mut rng, delta, (num_lookups + n_setup) * l_ver);
    let prover_vole = DerandVOLEReceiver::new(user_rvole_r);

    // ---- vole_zk perm-proof pair.
    let (perm_prover, perm_verifier) =
        build_ideal_perm_proof_pair(&mut rng, delta, n_setup + num_lookups, FAN_IN);

    // ---- Build prover and verifier.
    let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
        n_setup,
        prover_step,
        prover_vole,
        perm_prover,
    )
    .expect("prover new");
    let mut verifier = Verifier::<_, _, _, Char2Strategy<Gf2_64>>::new(
        n_setup,
        verifier_step,
        user_rvole_s,
        perm_verifier,
    )
    .expect("verifier new");

    prover.alloc(num_lookups).expect("prover alloc");
    verifier.alloc(num_lookups).expect("verifier alloc");

    BenchState {
        prover,
        verifier,
        delta,
        members,
        lookups,
        p_transcript: blake3::Hasher::new(),
        v_transcript: blake3::Hasher::new(),
    }
}

type SetTeardownPrep = set::TeardownPrepare<Gf2_64, Preparation<Gf2_64>>;
type SetTeardownMsg = set::TeardownMsg<Gf2_64, Proof<Gf2_64>>;

/// Prover-only online phase (timed for the prover bench): setup +
/// per-lookup calls + teardown_prepare + teardown on the prover side.
/// Returns the messages the verifier would consume.
fn run_prover_phase(
    mut prover: SetProver,
    members: Vec<Bundle<Gf2>>,
    lookups: &[Vec<Gf2>],
    transcript: &mut blake3::Hasher,
) -> (SetTeardownPrep, SetTeardownMsg) {
    prover.setup(members).expect("prover setup");
    for element in lookups {
        let prover_elem = ProverWire::<Gf2, Gf2_64>::constant(element.clone());
        prover.lookup(prover_elem).expect("prover lookup");
    }
    let prepare = prover
        .teardown_prepare(transcript)
        .expect("prover teardown_prepare");
    let msg = prover.teardown(transcript).expect("prover teardown");
    (prepare, msg)
}

/// Verifier-only online phase (timed for the verifier bench): setup +
/// per-lookup calls + teardown_prepare + teardown on the verifier
/// side. Consumes the prover's prepare + teardown messages.
fn run_verifier_phase(
    mut verifier: SetVerifier,
    members: Vec<Bundle<Gf2>>,
    lookups: &[Vec<Gf2>],
    delta: Gf2_64,
    prepare: SetTeardownPrep,
    msg: SetTeardownMsg,
    transcript: &mut blake3::Hasher,
) {
    verifier.setup(members).expect("verifier setup");
    for element in lookups {
        let verifier_elem = VerifierWire::<Gf2_64>::constant(element, delta);
        verifier.lookup(verifier_elem).expect("verifier lookup");
    }
    verifier
        .teardown_prepare(transcript, prepare)
        .expect("verifier teardown_prepare");
    verifier.teardown(msg, transcript).expect("verifier accept");
}

// ---------------------------------------------------------------------------
// Criterion entry points
// ---------------------------------------------------------------------------

fn bench_set_membership(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_membership");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(20));

    let suffix = format!("char2_{SET_SIZE}_members_{N_LOOKUPS}_lookups");

    // ---- Prover bench ----
    group.bench_function(format!("prover_{suffix}"), |b| {
        b.iter_batched(
            || offline_setup(SET_SIZE, N_LOOKUPS),
            |state| {
                let BenchState {
                    prover,
                    members,
                    lookups,
                    mut p_transcript,
                    ..
                } = state;
                let _out = run_prover_phase(prover, members, &lookups, &mut p_transcript);
            },
            BatchSize::PerIteration,
        );
    });

    // ---- Verifier bench ----
    // Setup pre-runs the prover (untimed) and hands the verifier the
    // prover's teardown messages.
    group.bench_function(format!("verifier_{suffix}"), |b| {
        b.iter_batched(
            || {
                let state = offline_setup(SET_SIZE, N_LOOKUPS);
                let BenchState {
                    prover,
                    verifier,
                    delta,
                    members,
                    lookups,
                    mut p_transcript,
                    v_transcript,
                } = state;
                let (prepare, msg) =
                    run_prover_phase(prover, members.clone(), &lookups, &mut p_transcript);
                (
                    verifier,
                    members,
                    lookups,
                    delta,
                    prepare,
                    msg,
                    v_transcript,
                )
            },
            |(verifier, members, lookups, delta, prepare, msg, mut v_transcript)| {
                run_verifier_phase(
                    verifier,
                    members,
                    &lookups,
                    delta,
                    prepare,
                    msg,
                    &mut v_transcript,
                );
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_set_membership);
criterion_main!(benches);
