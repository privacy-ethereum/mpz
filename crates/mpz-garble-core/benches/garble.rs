use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpz_circuits::circuits::AES128;
use mpz_garble_core::{Evaluator, Generator};
use mpz_memory_core::correlated::Delta;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut gb_group = c.benchmark_group("garble");

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let inputs: Vec<_> = (0..256).map(|_| rng.gen()).collect();

    gb_group.bench_function("aes128", |b| {
        let mut gen = Generator::default();
        b.iter(|| {
            let mut gen_iter = gen.generate(&AES128, delta, inputs.clone()).unwrap();

            let _: Vec<_> = gen_iter.by_ref().collect();

            black_box(gen_iter.finish().unwrap())
        })
    });

    gb_group.bench_function("aes128_batched", |b| {
        let mut gen = Generator::default();
        b.iter(|| {
            let mut gen_iter = gen
                .generate_batched(&AES128, delta, inputs.clone())
                .unwrap();

            let _: Vec<_> = gen_iter.by_ref().collect();

            black_box(gen_iter.finish().unwrap())
        })
    });

    drop(gb_group);

    let mut ev_group = c.benchmark_group("evaluate");

    ev_group.bench_function("aes128", |b| {
        let mut gen = Generator::default();
        let mut gen_iter = gen.generate(&AES128, delta, inputs.clone()).unwrap();
        let gates: Vec<_> = gen_iter.by_ref().collect();

        let choices: Vec<bool> = (0..256).map(|_| rng.gen()).collect();
        let inputs: Vec<_> = inputs
            .iter()
            .zip(choices)
            .map(|(input, choice)| input.auth(choice, &delta))
            .collect();

        let mut ev = Evaluator::default();
        b.iter(|| {
            let mut ev_consumer = ev.evaluate(&AES128, inputs.clone()).unwrap();

            for gate in &gates {
                ev_consumer.next(*gate);
            }

            black_box(ev_consumer.finish().unwrap());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
