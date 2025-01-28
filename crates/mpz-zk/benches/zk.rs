use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use mpz_circuits::circuits::AES128;
use mpz_common::context::test_mt_context;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{
    memory::{binary::U8, correlated::Delta, Array},
    prelude::*,
    Call,
};
use mpz_zk::{Prover, Verifier};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("zk");

    const BLOCK_COUNT: usize = 100;
    group.throughput(Throughput::Bytes(16 * BLOCK_COUNT as u64));
    group.bench_function("aes128", |b| {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut exec_p, mut exec_v) = test_mt_context(8);
        let mut ctx_p = block_on(exec_p.new_context()).unwrap();
        let mut ctx_v = block_on(exec_v.new_context()).unwrap();

        b.iter(|| {
            block_on(async {
                let (ot_send, ot_recv) = ideal_rcot(rng.gen(), delta.into_inner());

                let mut prover = Prover::new(ot_recv);
                let mut verifier = Verifier::new(delta, ot_send);

                futures::join!(
                    {
                        let key: Array<U8, 16> = prover.alloc().unwrap();
                        prover.mark_private(key).unwrap();
                        prover.assign(key, [0u8; 16]).unwrap();
                        prover.commit(key).unwrap();

                        for _ in 0..BLOCK_COUNT {
                            let msg: Array<U8, 16> = prover.alloc().unwrap();
                            prover.mark_public(msg).unwrap();
                            prover.assign(msg, [42u8; 16]).unwrap();
                            prover.commit(msg).unwrap();

                            let ciphertext: Array<U8, 16> = prover
                                .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                                .unwrap();

                            let _ = prover.decode(ciphertext).unwrap();
                        }

                        async {
                            prover.flush(&mut ctx_p).await.unwrap();
                            prover.execute(&mut ctx_p).await.unwrap();
                            prover.flush(&mut ctx_p).await.unwrap();
                        }
                    },
                    {
                        let key: Array<U8, 16> = verifier.alloc().unwrap();
                        verifier.mark_blind(key).unwrap();
                        verifier.commit(key).unwrap();

                        for _ in 0..BLOCK_COUNT {
                            let msg: Array<U8, 16> = verifier.alloc().unwrap();
                            verifier.mark_public(msg).unwrap();
                            verifier.assign(msg, [42u8; 16]).unwrap();
                            verifier.commit(msg).unwrap();

                            let ciphertext: Array<U8, 16> = verifier
                                .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                                .unwrap();

                            let _ = verifier.decode(ciphertext).unwrap();
                        }

                        async {
                            verifier.flush(&mut ctx_v).await.unwrap();
                            verifier.execute(&mut ctx_v).await.unwrap();
                            verifier.flush(&mut ctx_v).await.unwrap();
                        }
                    }
                );
            })
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
