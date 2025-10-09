use criterion::{Criterion, black_box, criterion_group, criterion_main};
use mpz_circuits::circuits::AES128;
use mpz_garble_core::{Evaluator, Garbler};
use mpz_memory_core::correlated::Delta;
use rand::{Rng, SeedableRng, rngs::StdRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut gb_group = c.benchmark_group("garble");

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let inputs: Vec<_> = (0..256).map(|_| rng.random()).collect();

    gb_group.bench_function("aes128", |b| {
        let mut gb = Garbler::default();
        b.iter(|| {
            let (mut gb_iter, _) = gb.generate(&AES128, delta, &inputs).unwrap();

            let _: Vec<_> = gb_iter.by_ref().collect();

            black_box(gb_iter.finish().unwrap())
        })
    });

    gb_group.bench_function("aes128_batched", |b| {
        let mut gb = Garbler::default();
        b.iter(|| {
            let (mut gb_iter, _) = gb.generate_batched(&AES128, delta, &inputs).unwrap();

            let _: Vec<_> = gb_iter.by_ref().collect();

            black_box(gb_iter.finish().unwrap())
        })
    });

    drop(gb_group);

    let mut ev_group = c.benchmark_group("evaluate");

    ev_group.bench_function("aes128", |b| {
        let mut gb = Garbler::default();
        let (mut gb_iter, gid) = gb.generate(&AES128, delta, &inputs).unwrap();
        let gates: Vec<_> = gb_iter.by_ref().collect();

        let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
        let inputs: Vec<_> = inputs
            .iter()
            .zip(choices)
            .map(|(input, choice)| input.auth(choice, &delta))
            .collect();

        let mut ev = Evaluator::default();
        b.iter(|| {
            let mut ev_consumer = ev.evaluate(&AES128, &inputs, gid.clone()).unwrap();

            for gate in &gates {
                ev_consumer.next(*gate);
            }

            black_box(ev_consumer.finish().unwrap());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
