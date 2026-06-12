//! End-to-end benchmarks for the two OLE constructions, fueled by ideal ROT.
//!
//! Both groups produce `N` chosen-input OLEs over P-256, and in both the ideal
//! ROT correlations (the "fuel") are generated in `iter_batched`'s untimed
//! setup, so the measurement covers the OLE protocol itself, not ROT
//! generation.
//!
//! - `gilboa` is a semi-honest batched ROLE — `N` random OLEs in a single
//!   send/recv — followed by the offset exchange that adjusts the random inputs
//!   to chosen ones (random OLE → OLE). gilboa uses the `IdealROT` +
//!   `AnySender`/`AnyReceiver` ROT abstraction, so "preflush" means hoisting
//!   its `flush()` into setup.
//! - `dhim` is the maliciously secure per-instance protocol, so its group runs
//!   `N` full six-flight executions in a loop, each fed a
//!   `preflushed_ideal_rot` pool and each sampling a fresh consistency prime +
//!   doing the 174-prime CRT weak multiplication (hence the small sample size).

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
use mpz_core::Block;
use mpz_fields::{UniformRand, p256::P256};
use mpz_ole_core::{
    ROLEReceiver, ROLESender,
    dhim::{
        OleReceiver, OleSender,
        config::p256::{P256_PRIMES, config},
        rot::{BlockToZpReceiver, BlockToZpSender},
    },
    gilboa,
};
use mpz_ot_core::{
    ideal::rot::{IdealROT, IdealROTReceiver, IdealROTSender, ideal_rot},
    rot::{AnyReceiver, AnySender, ROTReceiver, ROTSender},
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

/// Number of OLEs produced per benchmark sample.
const N: usize = 1000;

/// `ℓ = Σᵢ ⌈log₂ pᵢ⌉` — the ROT correlations one dhim OLE consumes.
fn rots_per_ole() -> usize {
    P256_PRIMES
        .iter()
        .map(|&p| (u64::BITS - (p - 1).leading_zeros()) as usize)
        .sum()
}

/// An ideal ROT pair pre-flushed with `count` correlations (dhim's split-source
/// ROT abstraction).
fn preflushed_ideal_rot(seed: [u8; 16], count: usize) -> (IdealROTSender, IdealROTReceiver) {
    let (mut sender, mut receiver) = ideal_rot(Block::from(seed));
    sender.alloc(count).unwrap();
    receiver.alloc(count).unwrap();
    let flush = sender.flush().unwrap();
    receiver.flush(flush).unwrap();
    (sender, receiver)
}

/// Semi-honest Gilboa: `N` ROLEs over P-256 in one batched send/recv, then the
/// offset exchange that adjusts them to chosen inputs.
fn gilboa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ole_gilboa");
    group.throughput(Throughput::Elements(N as u64));
    let mut rng = ChaCha12Rng::seed_from_u64(0);
    // Chosen OLE inputs the adjustment pins the random shares to.
    let a = P256::rand(&mut rng);
    let b = P256::rand(&mut rng);

    group.bench_function("p256", |bencher| {
        bencher.iter_batched(
            || {
                // Untimed: build the parties and generate the ROT fuel.
                let ideal = IdealROT::new(Block::random(&mut rng));
                let mut sender = gilboa::Sender::<_, P256>::new(
                    Block::random(&mut rng),
                    AnySender::new(ideal.clone()),
                );
                let mut receiver = gilboa::Receiver::<_, P256>::new(AnyReceiver::new(ideal));
                sender.alloc(N).unwrap();
                receiver.alloc(N).unwrap();
                sender.rot_mut().rot_mut().flush().unwrap();
                (sender, receiver)
            },
            |(mut sender, mut receiver)| {
                // Timed: the Gilboa multiplication + ROLE → OLE adjustment.
                let msg = sender.send().unwrap();
                receiver.recv(msg).unwrap();

                let s_out = sender.try_send_role(N).unwrap();
                let r_out = receiver.try_recv_role(N).unwrap();

                for (s_share, r_share) in s_out.shares.into_iter().zip(r_out.shares) {
                    let s_adj = s_share.adjust(a);
                    let r_adj = r_share.adjust(b);
                    let s_off = s_adj.offset();
                    let r_off = r_adj.offset();
                    black_box((s_adj.sender_finish(r_off), r_adj.receiver_finish(s_off)));
                }
            },
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

/// Maliciously secure DHIM OLE: `N` full six-flight executions over P-256.
fn dhim(c: &mut Criterion) {
    let cfg = config();
    let rots = rots_per_ole();
    let mut group = c.benchmark_group("ole_dhim");
    group.throughput(Throughput::Elements(N as u64));

    let mut input_rng = ChaCha12Rng::seed_from_u64(1);
    let mut srng = ChaCha12Rng::seed_from_u64(2);
    let mut rrng = ChaCha12Rng::seed_from_u64(3);

    group.bench_function("p256", |bencher| {
        bencher.iter_batched(
            // Untimed: one pre-flushed ROT pool per OLE.
            || -> Vec<(IdealROTSender, IdealROTReceiver)> {
                (0..N)
                    .map(|_| preflushed_ideal_rot([7u8; 16], rots))
                    .collect()
            },
            |pools| {
                // Timed: N full protocol runs (incl. per-OLE prime sampling).
                for (s_inner, r_inner) in pools {
                    let mut s_rot = BlockToZpSender::new(s_inner);
                    let mut r_rot = BlockToZpReceiver::new(r_inner);

                    let mut sender = OleSender::<P256>::new(cfg, &mut srng);
                    let mut receiver = OleReceiver::<P256>::new(cfg, &mut rrng);

                    let a = P256::rand(&mut input_rng);
                    let b = P256::rand(&mut input_rng);
                    let x = P256::rand(&mut input_rng);

                    sender.alloc(&mut s_rot).unwrap();
                    receiver.alloc(&mut r_rot).unwrap();

                    let m1 = receiver.round1(&mut r_rot).unwrap();
                    let m2 = sender.round1(&mut s_rot, &m1).unwrap();
                    let m3 = receiver.round2(&m2).unwrap();
                    let m4 = sender.round2(&m3).unwrap();
                    let m5 = receiver.round3(x, &m4).unwrap();
                    let m6 = sender.round3(a, b, &m5).unwrap();
                    black_box(receiver.finish(&m6).unwrap());
                }
            },
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

criterion_group! {
    name = gilboa_benches;
    config = Criterion::default().sample_size(50);
    targets = gilboa
}

criterion_group! {
    name = dhim_benches;
    config = Criterion::default().sample_size(10);
    targets = dhim
}

criterion_main!(gilboa_benches, dhim_benches);
