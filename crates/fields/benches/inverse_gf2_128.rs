use criterion::{Criterion, black_box, criterion_group, criterion_main};
use mpz_core::{Block, prg::Prg};
use mpz_fields::{Field, gf2_128::Gf2_128};
use rand::{Rng, SeedableRng};

fn bench_gf2_128_inverse(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);
    let a: Gf2_128 = rng.random();

    c.bench_function("inverse", move |bench| {
        bench.iter(|| {
            black_box(a.inverse());
        });
    });
}

criterion_group!(benches, bench_gf2_128_inverse);
criterion_main!(benches);
