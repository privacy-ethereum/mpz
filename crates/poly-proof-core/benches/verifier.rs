use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use mpz_fields::{ExtensionField, gf2::Gf2, gf2_64::Gf2_64};
use mpz_poly_proof_core::{
    ConstraintId, ConstraintsBuilder, ProofMessage, VerifierConstraints, VerifierVope,
    fixture::add_step_constraints, verifier::Verifier,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn random_gf64(rng: &mut impl Rng) -> Gf2_64 {
    Gf2_64(rng.random::<u64>())
}

struct TestData {
    /// Verifier-side constraint set.
    constraints: VerifierConstraints<Gf2_64>,
    /// Pre-generated verifier evaluations: (id, keys).
    evals: Vec<(ConstraintId, Vec<Gf2_64>)>,
    /// MAC key Δ.
    delta: Gf2_64,
    /// Prover's proof message (shape-correct; see `bench_verifier`).
    proof: ProofMessage<Gf2_64>,
    /// Verifier's VOPE share.
    vope: VerifierVope<Gf2_64>,
    /// Fiat-Shamir seed for the χ weights.
    seed: [u8; 32],
}

fn setup(num_evals: usize) -> TestData {
    let mut rng = StdRng::seed_from_u64(0xbe0c4);

    let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
    let step = add_step_constraints(&mut b).expect("fixtures must compile");
    let constraints = b.build_verifier();

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
            let n_vars = step.num_vars[template_idx];
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

    // A shape-correct proof + VOPE share for `finalize`. The verifier's
    // finalize cost (the χ-weighted fold over every buffered evaluation)
    // is independent of whether the check equation holds, so dummy values
    // of the right length exercise the full path without having to solve
    // a satisfying witness.
    let d = Verifier::new(delta, &constraints).required_vopes();
    let proof = ProofMessage {
        coefficients: (0..d).map(|_| random_gf64(&mut rng)).collect(),
    };
    let vope = VerifierVope {
        sum: random_gf64(&mut rng),
    };

    TestData {
        constraints,
        evals,
        delta,
        proof,
        vope,
        seed,
    }
}

fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier");
    group.sample_size(10);

    // ~232 evals per CPU step × 100k steps.
    let num_evals = 100_000 * 232;
    {
        let data = setup(num_evals);

        let batch: Vec<(ConstraintId, &[Gf2_64])> = data
            .evals
            .iter()
            .map(|(id, k)| (*id, k.as_slice()))
            .collect();

        let verifier = Verifier::new(data.delta, &data.constraints);

        group.bench_with_input(
            BenchmarkId::new("verifier", num_evals),
            &num_evals,
            |bench, _| {
                bench.iter_batched(
                    || verifier.clone(),
                    |mut v| {
                        v.accumulate(black_box(&batch)).unwrap();
                        // Dummy proof ⇒ the check returns `Err`, but the
                        // fold it measures is identical to a real verify.
                        let res = v.finalize(
                            black_box(&data.proof),
                            black_box(&data.vope),
                            black_box(data.seed),
                        );
                        let _ = black_box(res);
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
