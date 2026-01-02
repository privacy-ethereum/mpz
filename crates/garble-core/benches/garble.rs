//! Benchmarks for half-gates garbling.
//!
//! Run with: `cargo bench -p mpz-garble-core --bench garble`

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use mpz_circuits::AES128;
use mpz_garble_core::{Evaluator, Garbler, Key, SetupMsg};
use mpz_memory_core::correlated::Delta;
use rand::{Rng, SeedableRng, rngs::StdRng};

// Gate count thresholds
const THRESHOLDS: &[(u64, &str)] = &[(100_000, "100K"), (1_000_000, "1M"), (10_000_000, "10M")];

fn bench_garble(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble");
    group.sample_size(10);
    let circuit = &*AES128;

    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();

    let gates_per_circuit = circuit.and_count() as u64;

    for &(threshold, name) in THRESHOLDS {
        let iterations = threshold.div_ceil(gates_per_circuit) as usize;
        let actual_gates = iterations as u64 * gates_per_circuit;

        group.throughput(Throughput::Elements(actual_gates));

        // Iterator-based (one gate at a time)
        group.bench_function(BenchmarkId::new("iter", name), |b| {
            b.iter(|| {
                for _ in 0..iterations {
                    let mut gb = Garbler::new(delta);
                    let _ = gb.setup().unwrap();
                    let mut iter = gb.generate(circuit, &inputs).unwrap();
                    let _: Vec<_> = iter.by_ref().collect();
                    black_box(iter.finish().unwrap());
                }
            })
        });

        // Batched (multiple gates at a time)
        group.bench_function(BenchmarkId::new("batched", name), |b| {
            b.iter(|| {
                for _ in 0..iterations {
                    let mut gb = Garbler::new(delta);
                    let _ = gb.setup().unwrap();
                    let mut iter = gb.generate_batched(circuit, &inputs).unwrap();
                    let _: Vec<_> = iter.by_ref().collect();
                    black_box(iter.finish().unwrap());
                }
            })
        });
    }

    group.finish();

    // Evaluator benchmarks
    let mut ev_group = c.benchmark_group("evaluate");

    ev_group.bench_function("aes128", |b| {
        let mut gb = Garbler::new(delta);
        let setup = gb.setup().unwrap();
        let mut gb_iter = gb.generate(&AES128, &inputs).unwrap();
        let gates: Vec<_> = gb_iter.by_ref().collect();

        let choices: Vec<bool> = (0..256).map(|_| rng.random()).collect();
        let inputs: Vec<_> = inputs
            .iter()
            .zip(choices)
            .map(|(input, choice)| input.auth(choice, &delta))
            .collect();

        let msg = bincode::serialize(&setup).unwrap();

        b.iter(|| {
            let setup: SetupMsg = bincode::deserialize(&msg).unwrap();
            let mut ev = Evaluator::default();
            ev.setup(setup).unwrap();
            let mut ev_consumer = ev.evaluate(&AES128, &inputs).unwrap();

            for gate in &gates {
                ev_consumer.next(*gate);
            }

            black_box(ev_consumer.finish().unwrap());
        })
    });

    ev_group.finish();
}

criterion_group!(benches, bench_garble);
criterion_main!(benches);
