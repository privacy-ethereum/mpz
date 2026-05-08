use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use mpz_fields::{ExtensionField, gf2::Gf2, gf2_64::Gf2_64};
use mpz_poly_proof_core::{
    ConstraintId, Constraints, fixture::add_step_constraints, verifier::Verifier,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn random_gf64(rng: &mut impl Rng) -> Gf2_64 {
    Gf2_64(rng.random::<u64>())
}

struct TestData {
    /// The compiled constraint set.
    constraints: Constraints<Gf2_64>,
    /// Pre-generated verifier evaluations: (id, keys).
    evals: Vec<(ConstraintId, Vec<Gf2_64>)>,
    /// MAC key Δ.
    delta: Gf2_64,
    /// Batching seed.
    seed: [u8; 32],
}

fn setup(num_evals: usize) -> TestData {
    let mut rng = StdRng::seed_from_u64(0xbe0c4);

    let mut b = Constraints::<Gf2_64>::builder();
    let step = add_step_constraints(&mut b).expect("fixtures must compile");
    let constraints = b.build();

    // Per-template var counts (mirrors the upstream array sizes).
    let circuit_num_vars: Vec<usize> = vec![5, 4, 13, 14, 6, 4, 38, 3, 6, 8, 6, 4];

    let weighted_pool: Vec<usize> = step
        .counts
        .iter()
        .enumerate()
        .flat_map(|(i, &c)| std::iter::repeat_n(i, c))
        .collect();

    let delta = random_gf64(&mut rng);

    let evals: Vec<(ConstraintId, Vec<Gf2_64>)> = (0..num_evals)
        .map(|_| {
            let template_idx = weighted_pool[rng.random::<u64>() as usize % weighted_pool.len()];
            let n_vars = circuit_num_vars[template_idx];
            let keys: Vec<Gf2_64> = (0..n_vars)
                .map(|_| {
                    let mac = random_gf64(&mut rng);
                    let v = Gf2(rng.random::<bool>());
                    mac + Gf2_64::embed(v) * delta
                })
                .collect();
            (step.ids[template_idx], keys)
        })
        .collect();

    let seed: [u8; 32] = rng.random();

    TestData {
        constraints,
        evals,
        delta,
        seed,
    }
}

fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier");
    group.sample_size(10);

    for &num_evals in &[5_000_000, 10_000_000] {
        let data = setup(num_evals);

        let batch: Vec<(ConstraintId, &[Gf2_64])> = data
            .evals
            .iter()
            .map(|(id, k)| (*id, k.as_slice()))
            .collect();

        let verifier = Verifier::new(data.delta, &data.constraints);

        group.bench_with_input(
            BenchmarkId::new("accumulate", num_evals),
            &num_evals,
            |bench, _| {
                bench.iter_batched(
                    || verifier.clone(),
                    |mut v| {
                        v.accumulate(black_box(&batch), black_box(data.seed))
                            .unwrap();
                        black_box(&v);
                    },
                    criterion::BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_verifier);
criterion_main!(benches);
