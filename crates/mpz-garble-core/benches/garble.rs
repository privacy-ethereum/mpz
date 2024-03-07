use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpz_circuits::circuits::AES128;
use mpz_garble_core::{ChaChaEncoder, Encoder, Generator};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("garble_circuits");

    let encoder = ChaChaEncoder::new([0u8; 32]);
    let inputs = AES128
        .inputs()
        .iter()
        .map(|value| encoder.encode_by_type(0, &value.value_type()))
        .collect::<Vec<_>>();
    group.bench_function("aes128", |b| {
        b.iter(|| {
            let mut gen = Generator::new(AES128.clone(), encoder.delta(), &inputs).unwrap();

            let mut enc_gates = Vec::with_capacity(AES128.and_count());
            for gate in gen.by_ref() {
                enc_gates.push(gate);
            }

            black_box(gen.outputs().unwrap())
        })
    });
    group.bench_function("aes128_with_hash", |b| {
        b.iter(|| {
            let mut gen =
                Generator::new_with_hasher(AES128.clone(), encoder.delta(), &inputs).unwrap();

            let mut enc_gates = Vec::with_capacity(AES128.and_count());
            for gate in gen.by_ref() {
                enc_gates.push(gate);
            }

            black_box(gen.outputs().unwrap())
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
