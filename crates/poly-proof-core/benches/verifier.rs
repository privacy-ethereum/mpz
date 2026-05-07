use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use mpz_fields::gf2_64::Gf2_64;
use poly_proof_core::{
    SubfieldOf, circuit::Circuit, fixture::step_circuit_polynomials, verifier::Verifier,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn random_gf64(rng: &mut impl Rng) -> Gf2_64 {
    Gf2_64(rng.random::<u64>())
}

struct TestData {
    /// The 12 fixture circuits.
    circuits: Vec<Circuit<Gf2_64>>,
    /// Pre-generated verifier evaluations: (poly_id, keys).
    evals: Vec<(usize, Vec<Gf2_64>)>,
    /// MAC key Δ.
    delta: Gf2_64,
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

    let delta = random_gf64(&mut rng);

    let evals: Vec<(usize, Vec<Gf2_64>)> = (0..num_evals)
        .map(|_| {
            let poly_id = weighted_pool[rng.random::<u64>() as usize % weighted_pool.len()];
            let n_vars = circuit_num_vars[poly_id];
            let keys: Vec<Gf2_64> = (0..n_vars)
                .map(|_| {
                    let mac = random_gf64(&mut rng);
                    let v: bool = rng.random();
                    mac + v.embed() * delta
                })
                .collect();
            (poly_id, keys)
        })
        .collect();

    let chi = random_gf64(&mut rng);

    TestData {
        circuits,
        evals,
        delta,
        chi,
    }
}

fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier");
    group.sample_size(10);

    for &num_evals in &[5_000_000, 10_000_000] {
        let data = setup(num_evals);

        let batch: Vec<(usize, &[Gf2_64])> = data
            .evals
            .iter()
            .map(|(id, k)| (*id, k.as_slice()))
            .collect();

        let verifier = Verifier::new(data.delta, data.circuits.clone());

        group.bench_with_input(
            BenchmarkId::new("accumulate", num_evals),
            &num_evals,
            |bench, _| {
                bench.iter_batched(
                    || verifier.clone(),
                    |mut v| {
                        v.accumulate(black_box(&batch), black_box(data.chi))
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
