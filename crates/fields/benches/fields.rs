use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use mpz_core::{Block, prg::Prg};
use mpz_fields::{Accumulator, Field, gf2_64::Gf2_64, gf2_128::Gf2_128};
use rand::{Rng, SeedableRng};

const INNER_PRODUCT_LENS: &[usize] = &[1 << 8, 1 << 16, 1 << 20];

fn naive_inner_product<T: Field>(a: &[T], b: &[T]) -> T {
    a.iter()
        .zip(b.iter())
        .fold(T::zero(), |acc, (x, y)| acc + *x * *y)
}

/// Sum `Σ aᵢ·bᵢ` through the deferred-reduction [`Accumulator`]: each product
/// is folded in unreduced and a single reduction runs at the end.
fn accumulator_inner_product<T: Field>(a: &[T], b: &[T]) -> T {
    let mut acc = T::Accumulator::zero();
    for (x, y) in a.iter().zip(b.iter()) {
        acc.add_product(*x, *y);
    }
    acc.reduce()
}

fn naive_double_inner_product<T: Field>(a: &[T], b: &[T], c: &[T]) -> T {
    a.iter()
        .zip(b.iter())
        .zip(c.iter())
        .fold(T::zero(), |acc, ((x, y), z)| acc + *x * *y * *z)
}

fn bench_mul(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let a: Gf2_64 = rng.random();
        let b: Gf2_64 = rng.random();
        c.bench_function("gf2_64/mul", move |bench| {
            bench.iter(|| black_box(a) * black_box(b));
        });
    }

    {
        let a: Gf2_128 = rng.random();
        let b: Gf2_128 = rng.random();
        c.bench_function("gf2_128/mul", move |bench| {
            bench.iter(|| black_box(a) * black_box(b));
        });
    }
}

fn bench_square(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let a: Gf2_64 = rng.random();
        c.bench_function("gf2_64/square", move |bench| {
            bench.iter(|| black_box(a).square());
        });
    }

    {
        let a: Gf2_128 = rng.random();
        c.bench_function("gf2_128/square", move |bench| {
            bench.iter(|| black_box(a).square());
        });
    }
}

fn bench_inverse(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let a: Gf2_64 = rng.random();
        c.bench_function("gf2_64/inverse", move |bench| {
            bench.iter(|| black_box(a).inverse());
        });
    }

    {
        let a: Gf2_128 = rng.random();
        c.bench_function("gf2_128/inverse", move |bench| {
            bench.iter(|| black_box(a).inverse());
        });
    }
}

fn bench_inner_product(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let mut group = c.benchmark_group("gf2_64/inner_product");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("accelerated", len), &len, |bench, _| {
                bench.iter(|| Gf2_64::inner_product(black_box(&a), black_box(&b)));
            });
            group.bench_with_input(BenchmarkId::new("naive", len), &len, |bench, _| {
                bench.iter(|| naive_inner_product::<Gf2_64>(black_box(&a), black_box(&b)));
            });
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("gf2_128/inner_product");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("accelerated", len), &len, |bench, _| {
                bench.iter(|| Gf2_128::inner_product(black_box(&a), black_box(&b)));
            });
            group.bench_with_input(BenchmarkId::new("naive", len), &len, |bench, _| {
                bench.iter(|| naive_inner_product::<Gf2_128>(black_box(&a), black_box(&b)));
            });
        }
        group.finish();
    }
}

fn bench_double_inner_product(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let mut group = c.benchmark_group("gf2_64/double_inner_product");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();
            let cc: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("accelerated", len), &len, |bench, _| {
                bench.iter(|| {
                    Gf2_64::double_inner_product(black_box(&a), black_box(&b), black_box(&cc))
                });
            });
            group.bench_with_input(BenchmarkId::new("naive", len), &len, |bench, _| {
                bench.iter(|| {
                    naive_double_inner_product::<Gf2_64>(
                        black_box(&a),
                        black_box(&b),
                        black_box(&cc),
                    )
                });
            });
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("gf2_128/double_inner_product");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();
            let cc: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("accelerated", len), &len, |bench, _| {
                bench.iter(|| {
                    Gf2_128::double_inner_product(black_box(&a), black_box(&b), black_box(&cc))
                });
            });
            group.bench_with_input(BenchmarkId::new("naive", len), &len, |bench, _| {
                bench.iter(|| {
                    naive_double_inner_product::<Gf2_128>(
                        black_box(&a),
                        black_box(&b),
                        black_box(&cc),
                    )
                });
            });
        }
        group.finish();
    }
}

/// Deferred-reduction accumulator vs. an eager multiply-accumulate that reduces
/// after every product. Both compute `Σ aᵢ·bᵢ`; the gap is the per-product
/// reduction the accumulator defers. `inner_product` (the hand-tuned fused
/// kernel, which also defers but stays in vector registers) is the ceiling.
fn bench_accumulator(c: &mut Criterion) {
    let mut rng = Prg::from_seed(Block::ZERO);

    {
        let mut group = c.benchmark_group("gf2_64/accumulator");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_64> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("deferred", len), &len, |bench, _| {
                bench.iter(|| accumulator_inner_product::<Gf2_64>(black_box(&a), black_box(&b)));
            });
            group.bench_with_input(BenchmarkId::new("eager", len), &len, |bench, _| {
                bench.iter(|| naive_inner_product::<Gf2_64>(black_box(&a), black_box(&b)));
            });
            group.bench_with_input(BenchmarkId::new("inner_product", len), &len, |bench, _| {
                bench.iter(|| Gf2_64::inner_product(black_box(&a), black_box(&b)));
            });
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("gf2_128/accumulator");
        for &len in INNER_PRODUCT_LENS {
            let a: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();
            let b: Vec<Gf2_128> = (0..len).map(|_| rng.random()).collect();

            group.throughput(Throughput::Elements(len as u64));

            group.bench_with_input(BenchmarkId::new("deferred", len), &len, |bench, _| {
                bench.iter(|| accumulator_inner_product::<Gf2_128>(black_box(&a), black_box(&b)));
            });
            group.bench_with_input(BenchmarkId::new("eager", len), &len, |bench, _| {
                bench.iter(|| naive_inner_product::<Gf2_128>(black_box(&a), black_box(&b)));
            });
            group.bench_with_input(BenchmarkId::new("inner_product", len), &len, |bench, _| {
                bench.iter(|| Gf2_128::inner_product(black_box(&a), black_box(&b)));
            });
        }
        group.finish();
    }
}

criterion_group!(
    benches,
    bench_mul,
    bench_square,
    bench_inverse,
    bench_inner_product,
    bench_double_inner_product,
    bench_accumulator
);
criterion_main!(benches);
