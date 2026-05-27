//! Prover benchmark.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
use mpz_poly_proof_core::{
    ConstraintId, ConstraintsBuilder, ProverVope, fixture::add_step_constraints, prover::Prover,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn random_gf64(rng: &mut impl Rng) -> Gf2_64 {
    Gf2_64(rng.random::<u64>())
}

fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("prover");
    group.sample_size(10);

    // ~232 evals per CPU step × 100k steps.
    let num_evals = 100_000 * 232;
    {
        let mut rng = StdRng::seed_from_u64(0xbe0c4);

        let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
        let step = add_step_constraints(&mut b).expect("fixtures must compile");
        let constraints = b.build_prover();

        // Weighted template draw matching the per-step instantiation
        // counts (~232 evals per CPU step).
        let weighted_pool: Vec<usize> = step
            .counts
            .iter()
            .enumerate()
            .flat_map(|(i, &c)| std::iter::repeat_n(i, c))
            .collect();

        let evals: Vec<(ConstraintId, Vec<Gf2_64>, Vec<Gf2>)> = (0..num_evals)
            .map(|_| {
                let template_idx =
                    weighted_pool[rng.random::<u64>() as usize % weighted_pool.len()];
                let n_vars = step.num_vars[template_idx];
                let macs: Vec<Gf2_64> = (0..n_vars).map(|_| random_gf64(&mut rng)).collect();
                let values: Vec<Gf2> = (0..n_vars).map(|_| Gf2(rng.random::<bool>())).collect();
                (step.ids[template_idx], macs, values)
            })
            .collect();

        let seed: [u8; 32] = rng.random();

        let batch: Vec<(ConstraintId, &[Gf2_64], &[Gf2])> = evals
            .iter()
            .map(|(id, m, v)| (*id, m.as_slice(), v.as_slice()))
            .collect();

        let prover = Prover::new(&constraints);
        // VOPE mask consumed by `finalize` (one coeff per sent degree).
        let vope = ProverVope {
            coeffs: (0..prover.required_vopes())
                .map(|_| random_gf64(&mut rng))
                .collect(),
        };
        group.bench_with_input(
            BenchmarkId::new("prover", num_evals),
            &num_evals,
            |bench, _| {
                bench.iter_batched(
                    || prover.clone(),
                    |mut p| {
                        p.accumulate_kernels(black_box(&batch), black_box(seed))
                            .unwrap();
                        let proof = p.finalize(black_box(&vope)).unwrap();
                        black_box(proof);
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
