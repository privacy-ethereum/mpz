use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpz_common::{
    executor::{test_mt_executor, test_st_executor},
    Context,
};
use pollster::block_on;
use scoped_futures::ScopedFutureExt;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("context");

    // Measures the overhead of making a `Context::blocking` call, which
    // moves the context to a worker thread and back.
    group.bench_function("st/blocking", |b| {
        let (mut ctx, _) = test_st_executor(1024);
        b.iter(|| {
            block_on(async {
                ctx.blocking(|ctx| {
                    async move {
                        black_box(ctx.id());
                    }
                    .scope_boxed()
                })
                .await
                .unwrap();
            });
        })
    });

    // Measures the overhead of making a `Context::blocking` call, which
    // moves the context to a worker thread and back.
    group.bench_function("mt/blocking", |b| {
        let (mut exec_a, _) = test_mt_executor(8);

        let mut ctx = block_on(exec_a.new_thread()).unwrap();

        b.iter(|| {
            block_on(async {
                ctx.blocking(|ctx| {
                    async move {
                        black_box(ctx.id());
                    }
                    .scope_boxed()
                })
                .await
                .unwrap();
            });
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
