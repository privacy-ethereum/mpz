use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use mpz_fields::gf2_64::Gf2_64;
use poly_proof_core::{circuit::Circuit, fixture::step_circuit_polynomials, prover::Prover};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn random_gf64(rng: &mut impl Rng) -> Gf2_64 {
    Gf2_64(rng.random::<u64>())
}

struct TestData {
    /// The 12 fixture circuits.
    circuits: Vec<Circuit<Gf2_64>>,
    /// Pre-generated evaluations: (poly_id, macs, values).
    evals: Vec<(usize, Vec<Gf2_64>, Vec<bool>)>,
    /// Batching challenge.
    chi: Gf2_64,
}

fn setup(num_evals: usize) -> TestData {
    let mut rng = StdRng::seed_from_u64(0xbe0c4);

    let (circuits, counts) = step_circuit_polynomials::<Gf2_64>();
    let circuit_num_vars: Vec<usize> = circuits.iter().map(|c| c.num_vars()).collect();

    let weighted_pool: Vec<usize> = counts
        .iter()
        .enumerate()
        .flat_map(|(i, &c)| std::iter::repeat_n(i, c))
        .collect();

    let evals: Vec<(usize, Vec<Gf2_64>, Vec<bool>)> = (0..num_evals)
        .map(|_| {
            let poly_id = weighted_pool[rng.random::<u64>() as usize % weighted_pool.len()];
            let n_vars = circuit_num_vars[poly_id];
            let macs: Vec<Gf2_64> = (0..n_vars).map(|_| random_gf64(&mut rng)).collect();
            let values: Vec<bool> = (0..n_vars).map(|_| rng.random::<bool>()).collect();
            (poly_id, macs, values)
        })
        .collect();

    let chi = random_gf64(&mut rng);

    TestData {
        circuits,
        evals,
        chi,
    }
}

fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("prover");
    group.sample_size(10);

    for &num_evals in &[5_000_000, 10_000_000] {
        let data = setup(num_evals);

        let batch: Vec<(usize, &[Gf2_64], &[bool])> = data
            .evals
            .iter()
            .map(|(id, m, v)| (*id, m.as_slice(), v.as_slice()))
            .collect();

        let prover = Prover::new(data.circuits.clone());

        group.bench_with_input(
            BenchmarkId::new("accumulate", num_evals),
            &num_evals,
            |bench, _| {
                bench.iter_batched(
                    || prover.clone(),
                    |mut p| {
                        p.accumulate(black_box(&batch), black_box(data.chi))
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
