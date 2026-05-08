use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_poly_proof_core::{
    ConstraintId, Constraints, fixture::add_step_constraints, prover::Prover,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn random_gf64(rng: &mut impl Rng) -> Gf2_64 {
    Gf2_64(rng.random::<u64>())
}

struct TestData {
    /// The compiled constraint set.
    constraints: Constraints<Gf2_64>,
    /// Pre-generated evaluations: (id, macs, values).
    evals: Vec<(ConstraintId, Vec<Gf2_64>, Vec<Gf2>)>,
    /// Batching seed.
    seed: [u8; 32],
}

fn setup(num_evals: usize) -> TestData {
    let mut rng = StdRng::seed_from_u64(0xbe0c4);

    let mut b = Constraints::<Gf2_64>::builder();
    let step = add_step_constraints(&mut b).expect("fixtures must compile");
    let constraints = b.build();

    // Per-template num_vars from the compiled set.
    let circuit_num_vars: Vec<usize> = (0..step.ids.len())
        .map(|i| [5, 4, 13, 14, 6, 4, 38, 3, 6, 8, 6, 4][i])
        .collect();

    let weighted_pool: Vec<usize> = step
        .counts
        .iter()
        .enumerate()
        .flat_map(|(i, &c)| std::iter::repeat_n(i, c))
        .collect();

    let evals: Vec<(ConstraintId, Vec<Gf2_64>, Vec<Gf2>)> = (0..num_evals)
        .map(|_| {
            let template_idx = weighted_pool[rng.random::<u64>() as usize % weighted_pool.len()];
            let n_vars = circuit_num_vars[template_idx];
            let macs: Vec<Gf2_64> = (0..n_vars).map(|_| random_gf64(&mut rng)).collect();
            let values: Vec<Gf2> = (0..n_vars).map(|_| Gf2(rng.random::<bool>())).collect();
            (step.ids[template_idx], macs, values)
        })
        .collect();

    let seed: [u8; 32] = rng.random();

    TestData {
        constraints,
        evals,
        seed,
    }
}

fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("prover");
    group.sample_size(10);

    for &num_evals in &[5_000_000, 10_000_000] {
        let data = setup(num_evals);

        let batch: Vec<(ConstraintId, &[Gf2_64], &[Gf2])> = data
            .evals
            .iter()
            .map(|(id, m, v)| (*id, m.as_slice(), v.as_slice()))
            .collect();

        let prover = Prover::new(&data.constraints);

        group.bench_with_input(
            BenchmarkId::new("accumulate", num_evals),
            &num_evals,
            |bench, _| {
                bench.iter_batched(
                    || prover.clone(),
                    |mut p| {
                        p.accumulate(black_box(&batch), black_box(data.seed))
                            .unwrap();
                        black_box(&p);
                    },
                    criterion::BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_prover);
criterion_main!(benches);
