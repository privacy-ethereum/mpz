use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use mpz_circuits::circuits::AES128;
use mpz_common::context::{test_mt_context, test_st_context};
use mpz_garble::protocol::semihonest::{Evaluator, Generator};
use mpz_memory_core::{binary::*, correlated::Delta, Array};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{prelude::*, Call};
use rand::{rngs::StdRng, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("semihonest");
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.throughput(Throughput::Bytes(16));
    group.bench_function("aes", |b| {
        b.to_async(&rt).iter(|| async {
            let mut rng = StdRng::seed_from_u64(0);
            let delta = Delta::random(&mut rng);

            let (mut ctx_a, mut ctx_b) = test_st_context(8);
            let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

            let mut gen = Generator::new(cot_send, [0u8; 16], delta);
            let mut ev = Evaluator::new(cot_recv);

            let (gen_out, ev_out) = futures::join!(
                async {
                    let key: Array<U8, 16> = gen.alloc().unwrap();
                    let msg: Array<U8, 16> = gen.alloc().unwrap();

                    gen.mark_private(key).unwrap();
                    gen.mark_blind(msg).unwrap();

                    let ciphertext: Array<U8, 16> = gen
                        .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                        .unwrap();

                    let ciphertext = gen.decode(ciphertext).unwrap();

                    gen.assign(key, [0u8; 16]).unwrap();
                    gen.commit(key).unwrap();
                    gen.commit(msg).unwrap();

                    gen.flush(&mut ctx_a).await.unwrap();
                    gen.execute(&mut ctx_a).await.unwrap();
                    gen.flush(&mut ctx_a).await.unwrap();

                    ciphertext.await.unwrap()
                },
                async {
                    let key: Array<U8, 16> = ev.alloc().unwrap();
                    let msg: Array<U8, 16> = ev.alloc().unwrap();

                    ev.mark_blind(key).unwrap();
                    ev.mark_private(msg).unwrap();

                    let ciphertext: Array<U8, 16> = ev
                        .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                        .unwrap();

                    let ciphertext = ev.decode(ciphertext).unwrap();

                    ev.assign(msg, [42u8; 16]).unwrap();
                    ev.commit(key).unwrap();
                    ev.commit(msg).unwrap();

                    ev.flush(&mut ctx_b).await.unwrap();
                    ev.execute(&mut ctx_b).await.unwrap();
                    ev.flush(&mut ctx_b).await.unwrap();

                    ciphertext.await.unwrap()
                }
            );

            black_box((gen_out, ev_out));
        })
    });

    group.throughput(Throughput::Bytes(16 * 256));
    group.bench_function("aes/batched", |b| {
        b.to_async(&rt).iter(|| async {
            let mut rng = StdRng::seed_from_u64(0);
            let (mut exec_gen, mut exec_ev) = test_mt_context(8);
            let mut ctx_gen = exec_gen.new_context().await.unwrap();
            let mut ctx_ev = exec_ev.new_context().await.unwrap();

            let delta = Delta::random(&mut rng);
            let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

            let mut gen = Generator::new(cot_send, [0u8; 16], delta);
            let mut ev = Evaluator::new(cot_recv);

            futures::join!(
                async {
                    let key: Array<U8, 16> = gen.alloc().unwrap();

                    gen.mark_private(key).unwrap();
                    gen.assign(key, [0u8; 16]).unwrap();
                    gen.commit(key).unwrap();

                    for _ in 0..256 {
                        let msg: Array<U8, 16> = gen.alloc().unwrap();
                        gen.mark_blind(msg).unwrap();
                        gen.commit(msg).unwrap();

                        let ciphertext: Array<U8, 16> = gen
                            .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                            .unwrap();

                        let _ = gen.decode(ciphertext).unwrap();
                    }

                    gen.flush(&mut ctx_gen).await.unwrap();
                    gen.execute(&mut ctx_gen).await.unwrap();
                    gen.flush(&mut ctx_gen).await.unwrap();
                },
                async {
                    let key: Array<U8, 16> = ev.alloc().unwrap();
                    ev.mark_blind(key).unwrap();
                    ev.commit(key).unwrap();

                    for _ in 0..256 {
                        let msg: Array<U8, 16> = ev.alloc().unwrap();
                        ev.mark_private(msg).unwrap();
                        ev.assign(msg, [42u8; 16]).unwrap();
                        ev.commit(msg).unwrap();

                        let ciphertext: Array<U8, 16> = ev
                            .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                            .unwrap();

                        let _ = ev.decode(ciphertext).unwrap();
                    }

                    ev.flush(&mut ctx_ev).await.unwrap();
                    ev.execute(&mut ctx_ev).await.unwrap();
                    ev.flush(&mut ctx_ev).await.unwrap();
                }
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
