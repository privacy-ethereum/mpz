use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use mpz_core::aes::{AesEncryptor, FIXED_KEY_AES};

#[allow(clippy::all)]
fn criterion_benchmark(c: &mut Criterion) {
    let x = rand::random::<[u8; 16]>();
    let aes = AesEncryptor::new(x);
    let mut blk = rand::random::<[u8; 16]>();

    c.bench_function("aes::encrypt_block", move |bench| {
        bench.iter(|| {
            aes.encrypt_block(black_box(&mut blk));
            black_box(&blk);
        });
    });

    c.bench_function("aes::encrypt_many_blocks::<8>", move |bench| {
        let key = rand::random::<[u8; 16]>();
        let aes = AesEncryptor::new(key);
        let mut blks = std::array::from_fn::<_, 8, _>(|_| rand::random::<[u8; 16]>());

        bench.iter(|| {
            let z = aes.encrypt_many_blocks(black_box(&mut blks));
            black_box(z);
        });
    });

    c.bench_function("aes::para_encrypt::<1,8>", move |bench| {
        let key = rand::random::<[u8; 16]>();
        let aes = AesEncryptor::new(key);
        let aes = [aes];
        let mut blks = std::array::from_fn::<_, 8, _>(|_| rand::random::<[u8; 16]>());

        bench.iter(|| {
            let z = AesEncryptor::para_encrypt::<1, 8>(black_box(&aes), black_box(&mut blks));
            black_box(z);
        });
    });

    // Fixed-key CCR throughput over a realistic per-tile stretch batch.
    {
        let n = 8192;
        let mut src = vec![[0u8; 16]; n];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i as u128).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes();
        }
        let mut dst = vec![[0u8; 16]; n];

        let mut group = c.benchmark_group("ccr");
        group.throughput(Throughput::Bytes((n * 16) as u64));
        group.bench_function("blocks_to", |bench| {
            bench.iter(|| FIXED_KEY_AES.ccr_blocks_to(black_box(&src[..]), black_box(&mut dst[..])));
        });
        group.bench_function("mmo_blocks_to", |bench| {
            bench.iter(|| FIXED_KEY_AES.mmo_blocks_to(black_box(&src[..]), black_box(&mut dst[..])));
        });
        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
