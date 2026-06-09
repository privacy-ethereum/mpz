//! SHA-256 witness-generation benchmark.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use itybity::{FromBitIterator, ToBits};
use mpz_circuits::{
    WitnessCtx,
    sha256::{AND_PER_BLOCK, H0, compress},
};
use mpz_fields::gf2::Gf2;
use rand::{Rng, SeedableRng, rngs::StdRng};

const BYTES: usize = 16 * 1024;

fn make_blocks(num_blocks: usize) -> Vec<[Gf2; 512]> {
    let mut rng = StdRng::seed_from_u64(0);
    (0..num_blocks)
        .map(|_| {
            let block: [u32; 16] = core::array::from_fn(|_| rng.random());
            <[Gf2; 512]>::from_lsb0_iter(block.iter_lsb0())
        })
        .collect()
}

fn run_witness(state: [Gf2; 256], blocks: &[[Gf2; 512]], witness: &mut Vec<Gf2>) {
    witness.clear();
    let mut ctx = WitnessCtx { witness };
    let mut s = state;
    for msg in blocks {
        s = compress(&mut ctx, *msg, s);
    }
}

fn bench_sha256_witness(c: &mut Criterion) {
    let state: [Gf2; 256] = <[Gf2; 256]>::from_lsb0_iter(H0.iter_lsb0());
    let num_blocks = BYTES / 64;
    let blocks = make_blocks(num_blocks);
    let mut witness: Vec<Gf2> = Vec::with_capacity(num_blocks * AND_PER_BLOCK);

    let mut group = c.benchmark_group("sha256_witness");
    group.throughput(Throughput::Bytes(BYTES as u64));
    group.bench_function("16KiB", |b| {
        b.iter(|| run_witness(state, &blocks, &mut witness));
    });
    group.finish();
}

criterion_group!(benches, bench_sha256_witness);
criterion_main!(benches);
