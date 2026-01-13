//! Benchmarks for three-halves garbling scheme.
//!
//! Run with: `cargo bench -p mpz-garble-core --bench garbler_th`

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use mpz_circuits::AES128;
use mpz_core::Block;
use mpz_garble_core::{Key, three_halves};
use mpz_memory_core::correlated::{Delta, Mac};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Benchmark single AES circuit garbling
fn bench_garble_aes(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble_aes128");
    group.throughput(Throughput::Elements(AES128.and_count() as u64));

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);

    // Three-halves inputs (arbitrary Keys)
    let inputs: Vec<Key> = (0..256)
        .map(|_| {
            let block: Block = rng.random();
            block.into()
        })
        .collect();

    group.bench_function("three_halves", |b| {
        let mut gb = three_halves::Garbler::default();
        b.iter(|| {
            let mut bench_rng = StdRng::seed_from_u64(42);
            let mut iter = gb
                .generate(&AES128, delta, &inputs, &mut bench_rng)
                .unwrap();
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

    // Three-halves setup
    let inputs: Vec<Key> = (0..256)
        .map(|_| {
            let block: Block = rng.random();
            block.into()
        })
        .collect();

    let mut gb = three_halves::Garbler::default();
    let mut setup_rng = StdRng::seed_from_u64(42);
    let mut iter = gb
        .generate(&AES128, delta, &inputs, &mut setup_rng)
        .unwrap();
    let gates: Vec<_> = iter.by_ref().collect();
    let _ = iter.finish().unwrap();

    // Compute evaluator inputs from keys
    let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
    let delta_block = *delta.as_block();
    let eval_inputs: Vec<Mac> = inputs
        .iter()
        .zip(&choices)
        .map(|(key, &choice)| {
            let key_block = *key.as_block();
            if choice {
                (key_block ^ delta_block).into()
            } else {
                key_block.into()
            }
        })
        .collect();

    group.bench_function("three_halves", |b| {
        let mut ev = three_halves::Evaluator::default();
        b.iter(|| {
            let mut consumer = ev.evaluate(&AES128, &eval_inputs).unwrap();
            for gate in &gates {
                consumer.next(gate.clone());
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

    // Three-halves inputs
    let inputs: Vec<Key> = (0..256)
        .map(|_| {
            let block: Block = rng.random();
            block.into()
        })
        .collect();

    // Compute evaluator inputs from keys
    let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
    let delta_block = *delta.as_block();
    let eval_inputs: Vec<Mac> = inputs
        .iter()
        .zip(&choices)
        .map(|(key, &choice)| {
            let key_block = *key.as_block();
            if choice {
                (key_block ^ delta_block).into()
            } else {
                key_block.into()
            }
        })
        .collect();

    // Pre-generate gates for evaluation benchmarks
    let mut gb = three_halves::Garbler::default();
    let all_gates: Vec<Vec<_>> = (0..N)
        .map(|_| {
            let mut bench_rng = StdRng::seed_from_u64(42);
            let mut iter = gb
                .generate(&AES128, delta, &inputs, &mut bench_rng)
                .unwrap();
            let gates: Vec<_> = iter.by_ref().collect();
            let _ = iter.finish().unwrap();
            gates
        })
        .collect();

    // === Garble 100x ===
    {
        let mut group = c.benchmark_group("garble_100x_aes128");
        group.throughput(Throughput::Elements((N * AES128.and_count()) as u64));

        group.bench_function("three_halves", |b| {
            let mut gb = three_halves::Garbler::default();
            b.iter(|| {
                for _ in 0..N {
                    let mut bench_rng = StdRng::seed_from_u64(42);
                    let mut iter = gb
                        .generate(&AES128, delta, &inputs, &mut bench_rng)
                        .unwrap();
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

        group.bench_function("three_halves", |b| {
            let mut ev = three_halves::Evaluator::default();
            b.iter(|| {
                for gates in &all_gates {
                    let mut consumer = ev.evaluate(&AES128, &eval_inputs).unwrap();
                    for gate in gates {
                        consumer.next(gate.clone());
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

        group.bench_function("three_halves", |b| {
            let mut gb = three_halves::Garbler::default();
            let mut ev = three_halves::Evaluator::default();
            b.iter(|| {
                for _ in 0..N {
                    let mut bench_rng = StdRng::seed_from_u64(42);
                    let mut gb_iter = gb
                        .generate(&AES128, delta, &inputs, &mut bench_rng)
                        .unwrap();
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
