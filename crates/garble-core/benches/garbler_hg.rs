//! Benchmarks for half-gates garbling scheme.
//!
//! Run with: `cargo bench -p mpz-garble-core --bench garbler_hg`

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use mpz_circuits::AES128;
use mpz_garble_core::{Key, half_gates};
use mpz_memory_core::correlated::Delta;
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Benchmark single AES circuit garbling
fn bench_garble_aes(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble_aes128");
    group.throughput(Throughput::Elements(AES128.and_count() as u64));

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let seed: [u8; 16] = rng.random();

    let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();

    group.bench_function("half_gates", |b| {
        b.iter(|| {
            let mut gb = half_gates::Garbler::new(seed, delta);
            let _ = gb.setup().unwrap();
            let mut iter = gb.generate(&AES128, &inputs).unwrap();
            let _: Vec<_> = iter.by_ref().collect();
            black_box(iter.finish().unwrap())
        })
    });

    group.finish();
}

/// Benchmark single AES circuit evaluation
fn bench_evaluate_aes(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate_aes128");
    group.throughput(Throughput::Elements(AES128.and_count() as u64));

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let seed: [u8; 16] = rng.random();

    let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();
    let mut gb = half_gates::Garbler::new(seed, delta);
    let setup = gb.setup().unwrap();
    let mut iter = gb.generate(&AES128, &inputs).unwrap();
    let gates: Vec<_> = iter.by_ref().collect();
    let _ = iter.finish().unwrap();

    let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
    let eval_inputs: Vec<_> = inputs
        .iter()
        .zip(&choices)
        .map(|(k, &c)| k.auth(c, &delta))
        .collect();

    group.bench_function("half_gates", |b| {
        b.iter(|| {
            let mut ev = half_gates::Evaluator::default();
            ev.setup(setup.clone()).unwrap();
            let mut consumer = ev.evaluate(&AES128, &eval_inputs).unwrap();
            for gate in &gates {
                consumer.next(*gate);
            }
            black_box(consumer.finish().unwrap())
        })
    });

    group.finish();
}

/// Benchmark 100 AES circuits (throughput test)
fn bench_100_aes(c: &mut Criterion) {
    const N: usize = 100;

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let seed: [u8; 16] = rng.random();

    let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();
    let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
    let eval_inputs: Vec<_> = inputs
        .iter()
        .zip(&choices)
        .map(|(k, &c)| k.auth(c, &delta))
        .collect();

    // Pre-generate gates for evaluation benchmarks
    let mut gb = half_gates::Garbler::new(seed, delta);
    let setup = gb.setup().unwrap();
    let all_gates: Vec<Vec<_>> = (0..N)
        .map(|_| {
            let mut iter = gb.generate(&AES128, &inputs).unwrap();
            let gates: Vec<_> = iter.by_ref().collect();
            let _ = iter.finish().unwrap();
            gates
        })
        .collect();

    // === Garble 100x ===
    {
        let mut group = c.benchmark_group("garble_100x_aes128");
        group.throughput(Throughput::Elements((N * AES128.and_count()) as u64));

        group.bench_function("half_gates", |b| {
            b.iter(|| {
                for _ in 0..N {
                    let mut gb = half_gates::Garbler::new(seed, delta);
                    let _ = gb.setup().unwrap();
                    let mut iter = gb.generate(&AES128, &inputs).unwrap();
                    let _: Vec<_> = iter.by_ref().collect();
                    black_box(iter.finish().unwrap());
                }
            })
        });

        group.finish();
    }

    // === Evaluate 100x ===
    {
        let mut group = c.benchmark_group("evaluate_100x_aes128");
        group.throughput(Throughput::Elements((N * AES128.and_count()) as u64));

        group.bench_function("half_gates", |b| {
            b.iter(|| {
                for gates in &all_gates {
                    let mut ev = half_gates::Evaluator::default();
                    ev.setup(setup.clone()).unwrap();
                    let mut consumer = ev.evaluate(&AES128, &eval_inputs).unwrap();
                    for gate in gates {
                        consumer.next(*gate);
                    }
                    black_box(consumer.finish().unwrap());
                }
            })
        });

        group.finish();
    }

    // === Garble+Evaluate 100x ===
    {
        let mut group = c.benchmark_group("garble_and_evaluate_100x_aes128");
        group.throughput(Throughput::Elements((N * AES128.and_count()) as u64));

        group.bench_function("half_gates", |b| {
            b.iter(|| {
                for _ in 0..N {
                    let mut gb = half_gates::Garbler::new(seed, delta);
                    let setup = gb.setup().unwrap();
                    let mut ev = half_gates::Evaluator::default();
                    ev.setup(setup).unwrap();
                    let mut gb_iter = gb.generate(&AES128, &inputs).unwrap();
                    let mut ev_consumer = ev.evaluate(&AES128, &eval_inputs).unwrap();
                    for gate in gb_iter.by_ref() {
                        ev_consumer.next(gate);
                    }
                    black_box(gb_iter.finish().unwrap());
                    black_box(ev_consumer.finish().unwrap());
                }
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_garble_aes, bench_evaluate_aes, bench_100_aes);
criterion_main!(benches);
