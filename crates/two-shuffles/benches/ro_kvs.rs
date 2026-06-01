//! End-to-end benchmark for the RO-KVS protocol using ideal VOLE.
//!
//! Run with:
//!
//!     cargo bench --bench ro_kvs

use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_perm_proof_core::{
    backend::vole_zk::{Preparation, Proof, VoleZkProverBackend, VoleZkVerifierBackend},
    test_utils::build_ideal_perm_proof_pair,
};
use mpz_two_shuffles::{
    ProverWire, VerifierWire,
    ro_kvs::{self, Prover, Verifier},
    strategy::{
        Char2Strategy,
        version::{MultiplicativeStep, VersionStep},
    },
    test_utils::{generate_ro_kvs_witness, ideal_rvole_pair},
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

/// Number of key-value pairs in the store.
const N_STORE: usize = 40_000;
/// Number of lookups.
const N_LOOKUPS: usize = 100_000;
/// Value bit-width.
const VALUE_BITS: usize = 7;
/// Perm-proof fan-in.
const FAN_IN: usize = 8;

// Concrete prover/verifier types, named so `BenchState` can hold them.
type ProverBackend = VoleZkProverBackend<
    Gf2_64,
    Gf2_64,
    IdealRVOLEReceiver<Gf2_64, Gf2_64>,
    mpz_vole_core::ideal::rvope::IdealRVOPEReceiver<Gf2_64>,
>;
type VerifierBackend =
    VoleZkVerifierBackend<Gf2_64, Gf2_64, IdealRVOLESender<Gf2_64>, IdealRVOPESender<Gf2_64>>;

type RoKvsProver =
    Prover<IdealRVOLEReceiver<Gf2, Gf2_64>, Gf2_64, ProverBackend, Char2Strategy<Gf2_64>>;
type RoKvsVerifier =
    Verifier<IdealRVOLESender<Gf2_64>, Gf2_64, VerifierBackend, Char2Strategy<Gf2_64>>;

/// Everything the timed region needs. Built once per sample.
struct BenchState {
    prover: RoKvsProver,
    verifier: RoKvsVerifier,
    delta: Gf2_64,
    /// Value cleartexts for setup. Keys are implicit: position `i`
    /// is key `i`.
    content: Vec<Vec<Gf2>>,
    /// Lookup keys (each present in `content`).
    lookup_keys: Vec<Vec<Gf2>>,
    /// Caller-supplied Fiat-Shamir transcripts.
    p_transcript: blake3::Hasher,
    v_transcript: blake3::Hasher,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Offline phase: generate the witness, correlations, and backend,
/// construct prover and verifier, allocate VOLE / perm-proof state.
/// Excluded from the measured time.
fn offline_setup(n_store: usize, n_lookups: usize) -> BenchState {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();

    // ---- Witness: key→value content + lookup trace.
    let witness = generate_ro_kvs_witness(n_store, VALUE_BITS, n_lookups, &mut rng);
    let content = witness.content;
    let lookup_keys: Vec<Vec<Gf2>> = witness.lookups.into_iter().map(|[k]| k).collect();

    // ---- Version steps (sized to the worst-case per-key lookup count).
    let prover_step = MultiplicativeStep::new(n_lookups).expect("supported size");
    let verifier_step = MultiplicativeStep::new(n_lookups).expect("supported size");
    let l_ver = VersionStep::<Gf2>::len(&prover_step);

    // ---- User-facing input-gate VOLE.
    // Each lookup consumes (l_val + l_ver) slots; each setup entry's
    // teardown read consumes l_ver slots.
    let (user_rvole_s, user_rvole_r) = ideal_rvole_pair(
        &mut rng,
        delta,
        n_lookups * (VALUE_BITS + l_ver) + n_store * l_ver,
    );
    let prover_vole = DerandVOLEReceiver::new(user_rvole_r);

    // ---- vole_zk perm-proof pair.
    let (perm_prover, perm_verifier) =
        build_ideal_perm_proof_pair(&mut rng, delta, n_store + n_lookups, FAN_IN);

    // ---- Build prover and verifier.
    let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
        n_store,
        VALUE_BITS,
        prover_step,
        prover_vole,
        perm_prover,
    )
    .expect("prover new");
    let mut verifier = Verifier::<_, _, _, Char2Strategy<Gf2_64>>::new(
        n_store,
        VALUE_BITS,
        verifier_step,
        user_rvole_s,
        perm_verifier,
    )
    .expect("verifier new");

    prover.alloc(n_store, n_lookups).expect("prover alloc");
    verifier.alloc(n_store, n_lookups).expect("verifier alloc");

    BenchState {
        prover,
        verifier,
        delta,
        content,
        lookup_keys,
        p_transcript: blake3::Hasher::new(),
        v_transcript: blake3::Hasher::new(),
    }
}

type RoKvsTeardownPrep = ro_kvs::TeardownPrepare<Gf2_64, Preparation<Gf2_64>>;
type RoKvsTeardownMsg = ro_kvs::TeardownMsg<Gf2_64, Proof<Gf2_64>>;

/// Prover-only online phase (timed for the prover bench).
fn run_prover_phase(
    mut prover: RoKvsProver,
    content: Vec<Vec<Gf2>>,
    lookup_keys: &[Vec<Gf2>],
    transcript: &mut blake3::Hasher,
) -> (RoKvsTeardownPrep, RoKvsTeardownMsg) {
    prover.setup(content).expect("prover setup");
    for key_cleartext in lookup_keys {
        let prover_key = ProverWire::<Gf2, Gf2_64>::constant(key_cleartext.clone());
        prover.lookup(prover_key).expect("prover lookup");
    }
    let prepare = prover
        .teardown_prepare(transcript)
        .expect("prover teardown_prepare");
    let msg = prover.teardown(transcript).expect("prover teardown");
    (prepare, msg)
}

/// Verifier-only online phase (timed for the verifier bench).
/// Consumes the prover's prepare + teardown messages.
fn run_verifier_phase(
    mut verifier: RoKvsVerifier,
    content: Vec<Vec<Gf2>>,
    lookup_keys: &[Vec<Gf2>],
    delta: Gf2_64,
    prepare: RoKvsTeardownPrep,
    msg: RoKvsTeardownMsg,
    transcript: &mut blake3::Hasher,
) {
    verifier.setup(content).expect("verifier setup");
    for key_cleartext in lookup_keys {
        let verifier_key = VerifierWire::<Gf2_64>::constant(key_cleartext, delta);
        verifier.lookup(verifier_key).expect("verifier lookup");
    }
    verifier
        .teardown_prepare(transcript, prepare)
        .expect("verifier teardown_prepare");
    verifier.teardown(msg, transcript).expect("verifier accept");
}

// ---------------------------------------------------------------------------
// Criterion entry points
// ---------------------------------------------------------------------------

fn bench_ro_kvs(c: &mut Criterion) {
    let mut group = c.benchmark_group("ro_kvs");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(20));

    let suffix = format!("char2_{N_STORE}_pairs_{N_LOOKUPS}_lookups");

    // ---- Prover bench ----
    group.bench_function(format!("prover_{suffix}"), |b| {
        b.iter_batched(
            || offline_setup(N_STORE, N_LOOKUPS),
            |state| {
                let BenchState {
                    prover,
                    content,
                    lookup_keys,
                    mut p_transcript,
                    ..
                } = state;
                let _out = run_prover_phase(prover, content, &lookup_keys, &mut p_transcript);
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
                let state = offline_setup(N_STORE, N_LOOKUPS);
                let BenchState {
                    prover,
                    verifier,
                    delta,
                    content,
                    lookup_keys,
                    mut p_transcript,
                    v_transcript,
                } = state;
                let (prepare, msg) =
                    run_prover_phase(prover, content.clone(), &lookup_keys, &mut p_transcript);
                (
                    verifier,
                    content,
                    lookup_keys,
                    delta,
                    prepare,
                    msg,
                    v_transcript,
                )
            },
            |(verifier, content, lookup_keys, delta, prepare, msg, mut v_transcript)| {
                run_verifier_phase(
                    verifier,
                    content,
                    &lookup_keys,
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

criterion_group!(benches, bench_ro_kvs);
criterion_main!(benches);
