//! End-to-end benchmark for the RAM protocol using ideal VOLE.
//!
//! Run with:
//!
//!     cargo bench --bench ram

use std::time::Duration;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_perm_proof_core::{
    backend::vole_zk::{Preparation, Proof, VoleZkProverBackend, VoleZkVerifierBackend},
    test_utils::build_ideal_perm_proof_pair,
};
use mpz_two_shuffles::{
    ProverWire, VerifierWire,
    ram::{
        Clock, Flush, MultiplicativeClock, Prover, TeardownMsg as RamTeardownMsg,
        TeardownPrepare as RamTeardownPrepare, Verifier,
    },
    set,
    strategy::{
        Char2Strategy,
        version::{MultiplicativeStep, VersionStep},
    },
    test_utils::{generate_ram_witness, ideal_rvole_pair},
};
use mpz_vole_core::{
    DerandVOLEReceiver, DerandVOLESender,
    ideal::{
        rvole::{IdealRVOLEReceiver, IdealRVOLESender},
        rvope::IdealRVOPESender,
    },
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rangeset::set::RangeSet;

// ---------------------------------------------------------------------------
// Bench config
// ---------------------------------------------------------------------------

/// Memory size (number of byte-addressable cells).
const MEMORY_SIZE: usize = 4 * 1024;
/// Value bit-width.
const VALUE_BITS: usize = 32;
/// Number of accesses.
const N_ACCESSES: usize = 100_000;
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

type RamProver =
    Prover<IdealRVOLEReceiver<Gf2, Gf2_64>, Gf2_64, ProverBackend, Char2Strategy<Gf2_64>>;
type RamVerifier =
    Verifier<IdealRVOLESender<Gf2_64>, Gf2_64, VerifierBackend, Char2Strategy<Gf2_64>>;

type RamTeardown = RamTeardownMsg<Gf2_64, Proof<Gf2_64>>;

/// Everything the timed region needs.
struct BenchState {
    prover: RamProver,
    verifier: RamVerifier,
    delta: Gf2_64,
    /// Initial RAM content: one value per cell, in address order.
    content: Vec<Vec<Gf2>>,
    /// Access trace as `[op, addr, value]` cleartext bundles.
    accesses: Vec<[Vec<Gf2>; 3]>,
    /// Caller-supplied Fiat-Shamir transcripts.
    p_transcript: blake3::Hasher,
    v_transcript: blake3::Hasher,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Offline phase: generate the witness, all VOLE correlations (RAM,
/// mul-gate, mul-VOPE, set), build perm-proof backends for RAM and set,
/// construct the embedded `set::Prover` / `set::Verifier`, then the RAM
/// prover and verifier. Allocate everything.
fn offline_setup(memory_size: usize, n_accesses: usize) -> BenchState {
    let mut rng = ChaCha8Rng::seed_from_u64(0x42);
    let delta: Gf2_64 = rng.random();
    let t = n_accesses;

    // ---- Witness: initial content + access trace.
    let witness = generate_ram_witness(&RangeSet::from(0..memory_size), VALUE_BITS, t, &mut rng);

    // ---- Clocks (auto-sized n).
    let prover_clock = MultiplicativeClock::new(t).expect("supported clock size");
    let verifier_clock = MultiplicativeClock::new(t).expect("supported clock size");
    let l_clock = prover_clock.l_clock();

    // ---- RAM RVOLE (prover receives, verifier sends).
    let (ram_vole_s, ram_vole_r) =
        ideal_rvole_pair(&mut rng, delta, (t + memory_size) * (VALUE_BITS + l_clock));

    // ---- MulProver VOPE-side RVOLE (raw on both sides; consumed at
    // finalize for `EXTENSION_DEGREE` lifted-VOPE samples).
    let vope_count = <Gf2_64 as mpz_poly_proof_core::ExtensionField<Gf2>>::MONOMIAL_BASIS.len();
    let (mul_vope_s, mul_vope_r) = ideal_rvole_pair(&mut rng, delta, vope_count);

    // ---- MulProver mul-gate RVOLE (`t * l_val` prod-wire commits).
    let (mul_gate_s, mul_gate_r) = ideal_rvole_pair(&mut rng, delta, t * VALUE_BITS);

    // ---- Set version steps + set RVOLE.
    let prover_set_version = MultiplicativeStep::new(t).expect("supported version size");
    let verifier_set_version = MultiplicativeStep::new(t).expect("supported version size");
    let l_ver = VersionStep::<Gf2>::len(&prover_set_version);
    let (set_vole_s, set_vole_r) = ideal_rvole_pair(&mut rng, delta, (t + t) * l_ver);

    // ---- perm-proof pairs for RAM and set.
    let (ram_perm_prover, ram_perm_verifier) =
        build_ideal_perm_proof_pair(&mut rng, delta, memory_size + t, FAN_IN);
    let (set_perm_prover, set_perm_verifier) =
        build_ideal_perm_proof_pair(&mut rng, delta, t + t, FAN_IN);

    // ---- Build set Prover/Verifier.
    let prover_set = set::Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
        t,
        prover_set_version,
        DerandVOLEReceiver::new(set_vole_r),
        set_perm_prover,
    )
    .expect("set prover new");
    let verifier_set = set::Verifier::<_, _, _, Char2Strategy<Gf2_64>>::new(
        t,
        verifier_set_version,
        set_vole_s,
        set_perm_verifier,
    )
    .expect("set verifier new");

    // ---- Build RAM Prover/Verifier.
    let config = mpz_two_shuffles::ram::Config::<Gf2_64, Char2Strategy<Gf2_64>>::builder(
        RangeSet::from(0..memory_size),
        VALUE_BITS,
        t,
    )
    .build()
    .expect("ram config build");
    let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
        config.clone(),
        prover_clock,
        DerandVOLEReceiver::new(ram_vole_r),
        DerandVOLEReceiver::new(mul_gate_r),
        mul_vope_r,
        ram_perm_prover,
        prover_set,
    )
    .expect("ram prover new");
    let mut verifier = Verifier::<_, _, _, Char2Strategy<Gf2_64>>::new(
        config,
        verifier_clock,
        ram_vole_s,
        DerandVOLESender::new(mul_gate_s),
        mul_vope_s,
        ram_perm_verifier,
        verifier_set,
    )
    .expect("ram verifier new");

    prover.alloc().expect("ram prover alloc");
    verifier.alloc().expect("ram verifier alloc");

    BenchState {
        prover,
        verifier,
        delta,
        content: witness.initial_memory,
        accesses: witness.accesses,
        p_transcript: blake3::Hasher::new(),
        v_transcript: blake3::Hasher::new(),
    }
}

type RamTeardownPrep = RamTeardownPrepare<Gf2_64, Preparation<Gf2_64>>;

/// Prover-only online phase (timed for the prover bench): setup +
/// per-access calls + teardown on the prover side. Returns the
/// messages the verifier would consume.
fn run_prover_phase(
    mut prover: RamProver,
    content: Vec<Vec<Gf2>>,
    accesses: &[[Vec<Gf2>; 3]],
    transcript: &mut blake3::Hasher,
) -> (Flush<Gf2_64>, RamTeardownPrep, RamTeardown) {
    prover.setup(content).expect("ram prover setup");
    for [op, addr, w] in accesses {
        let prover_op = ProverWire::<Gf2, Gf2_64>::constant(op.clone());
        let prover_addr = ProverWire::<Gf2, Gf2_64>::constant(addr.clone());
        let prover_w = ProverWire::<Gf2, Gf2_64>::constant(w.clone());
        prover
            .access(prover_op, prover_addr, prover_w)
            .expect("prover access");
    }
    let flush = prover.flush().expect("prover flush");
    let prepare = prover
        .teardown_prepare(transcript)
        .expect("prover teardown_prepare");
    let (msg, _state) = prover.teardown(transcript).expect("prover teardown");
    (flush, prepare, msg)
}

/// Verifier-only online phase (timed for the verifier bench): setup +
/// per-access calls + flush + teardown_prepare + teardown on the
/// verifier side. Consumes the prover's flush + prepare + teardown
/// messages.
fn run_verifier_phase(
    mut verifier: RamVerifier,
    content: Vec<Vec<Gf2>>,
    accesses: &[[Vec<Gf2>; 3]],
    delta: Gf2_64,
    flush: Flush<Gf2_64>,
    prepare: RamTeardownPrep,
    msg: RamTeardown,
    transcript: &mut blake3::Hasher,
) {
    verifier.setup(content).expect("ram verifier setup");
    for [op, addr, w] in accesses {
        let verifier_op = VerifierWire::<Gf2_64>::constant(op, delta);
        let verifier_addr = VerifierWire::<Gf2_64>::constant(addr, delta);
        let verifier_w = VerifierWire::<Gf2_64>::constant(w, delta);
        verifier
            .access(verifier_op, verifier_addr, verifier_w)
            .expect("verifier access");
    }
    verifier.flush(flush).expect("verifier flush");
    verifier
        .teardown_prepare(transcript, prepare)
        .expect("verifier teardown_prepare");
    verifier.teardown(transcript, msg).expect("verifier accept");
}

// ---------------------------------------------------------------------------
// Criterion entry points
// ---------------------------------------------------------------------------

fn bench_ram(c: &mut Criterion) {
    let mut group = c.benchmark_group("ram");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(30));

    let suffix = format!("char2_{MEMORY_SIZE}_cells_{N_ACCESSES}_accesses");

    // ---- Prover bench ----
    group.bench_function(format!("prover_{suffix}"), |b| {
        b.iter_batched(
            || offline_setup(MEMORY_SIZE, N_ACCESSES),
            |state| {
                let BenchState {
                    prover,
                    content,
                    accesses,
                    mut p_transcript,
                    ..
                } = state;
                let _out = run_prover_phase(prover, content, &accesses, &mut p_transcript);
            },
            BatchSize::PerIteration,
        );
    });

    // ---- Verifier bench ----
    // Setup pre-runs the prover (untimed) and yields the verifier-side
    // state plus the prover's flush + teardown messages.
    group.bench_function(format!("verifier_{suffix}"), |b| {
        b.iter_batched(
            || {
                let state = offline_setup(MEMORY_SIZE, N_ACCESSES);
                let BenchState {
                    prover,
                    verifier,
                    delta,
                    content,
                    accesses,
                    mut p_transcript,
                    v_transcript,
                } = state;
                let (flush, prepare, msg) =
                    run_prover_phase(prover, content.clone(), &accesses, &mut p_transcript);
                (
                    verifier,
                    content,
                    accesses,
                    delta,
                    flush,
                    prepare,
                    msg,
                    v_transcript,
                )
            },
            |(verifier, content, accesses, delta, flush, prepare, msg, mut v_transcript)| {
                run_verifier_phase(
                    verifier,
                    content,
                    &accesses,
                    delta,
                    flush,
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

criterion_group!(benches, bench_ram);
criterion_main!(benches);
