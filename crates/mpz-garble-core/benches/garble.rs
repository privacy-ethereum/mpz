use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpz_circuits::circuits::AES128;
use mpz_garble_core::{ChaChaEncoder, Encoder, Evaluator, Generator};

fn criterion_benchmark(c: &mut Criterion) {
    let mut gb_group = c.benchmark_group("garble");

    let encoder = ChaChaEncoder::new([0u8; 32]);
    let full_inputs = AES128
        .inputs()
        .iter()
        .map(|value| encoder.encode_by_type(0, &value.value_type()))
        .collect::<Vec<_>>();

    let active_inputs = vec![
        full_inputs[0].clone().select([0u8; 16]).unwrap(),
        full_inputs[1].clone().select([0u8; 16]).unwrap(),
    ];

    gb_group.bench_function("aes128", |b| {
        let mut gen = Generator::default();
        b.iter(|| {
            let mut gen_iter = gen
                .generate(&AES128, encoder.delta(), full_inputs.clone())
                .unwrap();

            let _: Vec<_> = gen_iter.by_ref().collect();

            black_box(gen_iter.finish().unwrap())
        })
    });

    gb_group.bench_function("aes128_batched", |b| {
        let mut gen = Generator::default();
        b.iter(|| {
            let mut gen_iter = gen
                .generate_batched(&AES128, encoder.delta(), full_inputs.clone())
                .unwrap();

            let _: Vec<_> = gen_iter.by_ref().collect();

            black_box(gen_iter.finish().unwrap())
        })
    });

    gb_group.bench_function("aes128_with_hash", |b| {
        let mut gen = Generator::default();
        b.iter(|| {
            let mut gen_iter = gen
                .generate(&AES128, encoder.delta(), full_inputs.clone())
                .unwrap();

            gen_iter.enable_hasher();

            let _: Vec<_> = gen_iter.by_ref().collect();

            black_box(gen_iter.finish().unwrap())
        })
    });

    drop(gb_group);

    let mut ev_group = c.benchmark_group("evaluate");

    ev_group.bench_function("aes128", |b| {
        let mut gen = Generator::default();
        let mut gen_iter = gen
            .generate(&AES128, encoder.delta(), full_inputs.clone())
            .unwrap();
        let gates: Vec<_> = gen_iter.by_ref().collect();

        let mut ev = Evaluator::default();
        b.iter(|| {
            let mut ev_consumer = ev.evaluate(&AES128, active_inputs.clone()).unwrap();

            for gate in &gates {
                ev_consumer.next(*gate);
            }

            black_box(ev_consumer.finish().unwrap());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
