use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use mpz_circuits::circuits::AES128;
use mpz_common::context::{test_mt_context, test_st_context};
use mpz_garble::protocol::authenticated::{AuthEval, AuthGen};
use mpz_memory_core::{Array, binary::*, correlated::Delta};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{Call, prelude::*};
use rand::{SeedableRng, rngs::StdRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("authenticated");
    group.sample_size(10);
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.throughput(Throughput::Bytes(16));
    group.bench_function("aes", |b| {
        b.to_async(&rt).iter(|| async {
            let mut rng = StdRng::seed_from_u64(0);
        
            let delta_a = Delta::random(&mut rng).set_lsb(true);
            let delta_b = Delta::random(&mut rng).set_lsb(false);
    
            let (mut ctx_a, mut ctx_b) = test_st_context(8);
            let (cot_gen_send, cot_eval_recv) = ideal_cot(delta_a.into_inner());
            let (cot_eval_send, cot_gen_recv) = ideal_cot(delta_b.into_inner());
    
            let mut gb = AuthGen::new([0u8; 16], delta_a, cot_gen_send, cot_gen_recv);
            let mut ev = AuthEval::new([0u8; 16], delta_b, cot_eval_send, cot_eval_recv);
    
            let (gen_out, ev_out) = futures::join!(
                async {
                    let key: Array<U8, 16> = gb.alloc().unwrap();
                    let msg: Array<U8, 16> = gb.alloc().unwrap();
    
                    gb.mark_private(key).unwrap();
                    gb.mark_blind(msg).unwrap();
    
                    let ciphertext: Array<U8, 16> = gb
                        .call(
                            Call::builder(AES128.clone())
                                .arg(key)
                                .arg(msg)
                                .build()
                                .unwrap(),
                        )
                        .unwrap();
    
                    let mut ciphertext = gb.decode(ciphertext).unwrap();
    
                    gb.assign(key, [0u8; 16]).unwrap();
                    gb.commit(key).unwrap();
                    gb.commit(msg).unwrap();
    
                    gb.execute_all(&mut ctx_a).await.unwrap();
                    ciphertext.try_recv().unwrap().unwrap()
                },
                async {
                    let key: Array<U8, 16> = ev.alloc().unwrap();
                    let msg: Array<U8, 16> = ev.alloc().unwrap();
    
                    ev.mark_blind(key).unwrap();
                    ev.mark_private(msg).unwrap();
    
                    let ciphertext: Array<U8, 16> = ev
                        .call(
                            Call::builder(AES128.clone())
                                .arg(key)
                                .arg(msg)
                                .build()
                                .unwrap(),
                        )
                        .unwrap();
    
                    let mut ciphertext = ev.decode(ciphertext).unwrap();
    
                    ev.assign(msg, [42u8; 16]).unwrap();
                    ev.commit(key).unwrap();
                    ev.commit(msg).unwrap();
    
                    ev.execute_all(&mut ctx_b).await.unwrap();
                    ciphertext.try_recv().unwrap().unwrap()
                }
            );
    
            black_box((gen_out, ev_out));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
