//! Prover-side benchmark for the permutation-proof protocol.
//!
//! Uses the [`VoleZkProverBackend`] with the ideal RVOLE / RVOPE
//! functionalities, so the numbers measure protocol overhead in
//! isolation from any concrete VOLE construction.

use blake3::Hasher;
use criterion::{
    BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use mpz_fields::gf2_64::Gf2_64;
use mpz_vole_core::ideal::{
    rvole::{IdealRVOLEReceiver, IdealRVOLESender, ideal_rvole},
    rvope::{IdealRVOPEReceiver, IdealRVOPESender, ideal_rvope},
};
use perm_proof_core::{
    Prover,
    backend::vole_zk::VoleZkProverBackend,
    test_utils::{
        Committed, commit_values, vole_zk_rvole_pregenerate_count,
        vole_zk_rvope_pregenerate_degree,
    },
};
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha8Rng;

/// Fan-in of the product circuit. 
const EPS: usize = 16;

/// Criterion reports per-element throughput via `Throughput::Elements(n)`.
const INPUT_SIZES: &[usize] = &[10_000, 100_000, 200_000];

/// Seed for the driver RNG. Fixed so input distributions and ideal
/// correlations are reproducible run-to-run.
const BENCH_SEED: u64 = 0x5E1F_B0FB_1F15_D00D;

type ProverBackend = VoleZkProverBackend<
    Gf2_64,
    Gf2_64,
    IdealRVOLEReceiver<Gf2_64, Gf2_64>,
    IdealRVOPEReceiver<Gf2_64>,
>;

/// Per-`(n, L)` data that's immutable across bench iterations: the
/// shared MAC secret, the input permutation, its authenticated wires,
/// and the transcript state from the ideal-VOLE commit.
struct Fixture {
    delta: Gf2_64,
    x_values: Vec<Vec<Gf2_64>>,
    x_macs: Vec<Vec<Gf2_64>>,
    y_values: Vec<Vec<Gf2_64>>,
    y_macs: Vec<Vec<Gf2_64>>,
    transcript: Hasher,
}

/// One-shot: pick `delta`, generate the input permutation, authenticate
/// both vectors via the ideal-VOLE `commit_values` helper, and bundle
/// the result. Called once per `(n, L)` bench point.
fn build_fixture<const L: usize>(rng: &mut ChaCha8Rng, n: usize) -> Fixture {
    let delta: Gf2_64 = rng.random();

    let x_values: Vec<Vec<Gf2_64>> = (0..n)
        .map(|_| (0..L).map(|_| rng.random()).collect())
        .collect();
    let mut perm_indices: Vec<usize> = (0..n).collect();
    perm_indices.shuffle(rng);
    let y_values: Vec<Vec<Gf2_64>> = perm_indices.iter().map(|&i| x_values[i].clone()).collect();

    let Committed {
        macs: [x_macs, y_macs],
        keys: _,
        transcript,
    } = commit_values([&x_values[..], &y_values[..]], delta, rng);

    Fixture {
        delta,
        x_values,
        x_macs,
        y_values,
        y_macs,
        transcript,
    }
}

/// Per-iter: build a fresh ideal RVOLE / RVOPE pair under the fixture's
/// `delta`, pregenerate enough correlations for exactly one prover run,
/// and wire a new `Prover` to the receiver halves.
fn build_correlations_and_prover(
    rng: &mut ChaCha8Rng,
    delta: Gf2_64,
    n: usize,
) -> Prover<Gf2_64, Gf2_64, ProverBackend> {
    let rvole_seed: u64 = rng.random();
    let rvope_seed: u64 = rng.random();

    let rvole_count = vole_zk_rvole_pregenerate_count(n, EPS);
    let (mut rvole_s, mut rvole_r): (IdealRVOLESender<Gf2_64>, _) =
        ideal_rvole::<Gf2_64, Gf2_64>(rvole_seed, delta);
    rvole_s.pregenerate(rvole_count);
    rvole_r
        .pregenerate(rvole_count, delta)
        .expect("ideal RVOLE receiver pregenerate");

    let rvope_degree = vole_zk_rvope_pregenerate_degree::<Gf2_64>(EPS);
    let (mut rvope_s, mut rvope_r): (IdealRVOPESender<Gf2_64>, _) =
        ideal_rvope::<Gf2_64>(rvope_seed, delta);
    rvope_s.pregenerate(1, rvope_degree);
    rvope_r.pregenerate(1, rvope_degree);

    // Keep the senders alive to the end of setup so they materialize
    // the receiver-side pool via shared seed; drop once done.
    drop(rvole_s);
    drop(rvope_s);

    let mut prover = Prover::new(
        VoleZkProverBackend::<Gf2_64, Gf2_64, _, _>::new(EPS, rvole_r, rvope_r).unwrap(),
    );
    prover.alloc(n).expect("prover alloc must succeed");
    prover
}

/// Bench `n` inputs of tuple width `L`.
fn bench_prove(c: &mut Criterion) {
    fn case<const L: usize>(
        group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
        n: usize,
    ) {
        let id = BenchmarkId::new(format!("L={L}"), n);
        group.bench_with_input(id, &n, |b, &n| {
            let mut rng = ChaCha8Rng::seed_from_u64(BENCH_SEED ^ (n as u64) ^ (L as u64));
            let fixture = build_fixture::<L>(&mut rng, n);
            b.iter_batched(
                || {
                    let prover = build_correlations_and_prover(&mut rng, fixture.delta, n);
                    (prover, fixture.transcript.clone())
                },
                |(prover, transcript)| {
                    let (_preparation, prover) = prover
                        .prepare(
                            transcript,
                            (&fixture.x_values, &fixture.x_macs),
                            (&fixture.y_values, &fixture.y_macs),
                        )
                        .expect("prepare must succeed");
                    let proof = prover.prove().expect("prove must succeed");
                    black_box(proof);
                },
                criterion::BatchSize::PerIteration,
            );
        });
    }

    let mut group = c.benchmark_group("prove");
    group.sample_size(10);
    for &n in INPUT_SIZES {
        group.throughput(Throughput::Elements(n as u64));
        case::<1>(&mut group, n);
        case::<2>(&mut group, n);
    }
    group.finish();
}

criterion_group!(benches, bench_prove);
criterion_main!(benches);
