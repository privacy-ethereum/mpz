//! Verifier-side benchmark for the permutation-proof protocol.
//!
//! Uses the [`VoleZkVerifierBackend`] with the ideal RVOLE / RVOPE
//! functionalities, so the numbers measure protocol overhead in
//! isolation from any concrete VOLE construction.

use blake3::Hasher;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use mpz_fields::gf2_64::Gf2_64;
use mpz_perm_proof_core::{
    Proof as Envelope, Prover, Verifier,
    backend::vole_zk::{
        Preparation, Proof as BackendProof, VoleZkProverBackend, VoleZkVerifierBackend,
    },
    test_utils::{
        Committed, commit_values, vole_zk_rvole_pregenerate_count, vole_zk_rvope_pregenerate_degree,
    },
};
use mpz_vole_core::ideal::{
    rvole::{IdealRVOLESender, ideal_rvole},
    rvope::{IdealRVOPESender, ideal_rvope},
};
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha8Rng;

const EPS: usize = 8;

const INPUT_SIZES: &[usize] = &[100_000, 200_000];

const BENCH_SEED: u64 = 0x5E1F_B0FB_1F15_D00D;

type VerifierBackendT =
    VoleZkVerifierBackend<Gf2_64, Gf2_64, IdealRVOLESender<Gf2_64>, IdealRVOPESender<Gf2_64>>;

type FullProof = Envelope<Gf2_64, BackendProof<Gf2_64>>;

/// Per-`(n, L)` data that's immutable across iterations: the verifier
/// inputs (keys + transcript), the prover-produced DTOs the verifier
/// consumes, and the RVOLE/RVOPE seeds so per-iter setup can rebuild
/// matching senders. Generated once per bench point.
struct Fixture {
    delta: Gf2_64,
    x_keys: Vec<Vec<Gf2_64>>,
    y_keys: Vec<Vec<Gf2_64>>,
    transcript: Hasher,
    preparation: Preparation<Gf2_64>,
    proof: FullProof,
    rvole_seed: u64,
    rvope_seed: u64,
}

/// One-shot: generate inputs, authenticate them via `commit_values`,
/// then run an honest prover through `prepare` + `prove` to produce the
/// `preparation` and `Proof` the verifier will consume.
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
        keys: [x_keys, y_keys],
        transcript,
    } = commit_values([&x_values[..], &y_values[..]], delta, rng);

    let rvole_seed: u64 = rng.random();
    let rvope_seed: u64 = rng.random();

    // Build the prover's correlation receivers (senders are only kept
    // alive long enough to materialize the matching pool via shared
    // seed, then dropped — their per-iter counterpart is rebuilt in
    // `build_verifier` below).
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

    drop(rvole_s);
    drop(rvope_s);

    let mut prover = Prover::new(
        VoleZkProverBackend::<Gf2_64, Gf2_64, _, _>::new(EPS, rvole_r, rvope_r).unwrap(),
    );
    prover.alloc(n).expect("prover alloc must succeed");

    let mut tp = transcript.clone();
    let preparation = prover
        .prepare(&mut tp, (&x_values, &x_macs), (&y_values, &y_macs))
        .expect("prover prepare must succeed");
    let proof = prover.prove(&mut tp).expect("prover prove must succeed");

    Fixture {
        delta,
        x_keys,
        y_keys,
        transcript,
        preparation,
        proof,
        rvole_seed,
        rvope_seed,
    }
}

/// Per-iter: rebuild the verifier side under the fixture's `delta` and
/// seeds. The sender pool pregenerated here matches the receiver pool
/// the prover consumed in `build_fixture` (shared `(seed, delta)` →
/// identical correlations), so the adjustments in the prover's
/// `preparation` apply correctly.
///
/// The receiver halves are pregenerated but immediately dropped; the
/// prover bench's comment applies here inverted: keep both halves alive
/// through pregenerate so the pair materializes consistently, then
/// discard the one we don't need.
fn build_verifier(
    delta: Gf2_64,
    rvole_seed: u64,
    rvope_seed: u64,
    n: usize,
) -> Verifier<Gf2_64, Gf2_64, VerifierBackendT> {
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

    drop(rvole_r);
    drop(rvope_r);

    let mut verifier = Verifier::new(
        VoleZkVerifierBackend::<Gf2_64, Gf2_64, _, _>::new(EPS, delta, rvole_s, rvope_s).unwrap(),
    );
    verifier.alloc(n).expect("verifier alloc must succeed");
    verifier
}

/// Bench `n` inputs of tuple width `L`.
fn bench_verify(c: &mut Criterion) {
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
                    let verifier =
                        build_verifier(fixture.delta, fixture.rvole_seed, fixture.rvope_seed, n);
                    (
                        verifier,
                        fixture.transcript.clone(),
                        fixture.preparation.clone(),
                        fixture.proof.clone(),
                    )
                },
                |(mut verifier, mut transcript, preparation, proof)| {
                    verifier
                        .prepare(
                            &mut transcript,
                            &fixture.x_keys,
                            &fixture.y_keys,
                            preparation,
                        )
                        .expect("verifier prepare must succeed");
                    verifier
                        .verify(proof, &mut transcript)
                        .expect("verify must succeed");
                    black_box(());
                },
                criterion::BatchSize::PerIteration,
            );
        });
    }

    let mut group = c.benchmark_group("verifier");
    group.sample_size(10);
    for &n in INPUT_SIZES {
        group.throughput(Throughput::Elements(n as u64));
        case::<1>(&mut group, n);
        case::<2>(&mut group, n);
    }
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
