use criterion::{criterion_group, criterion_main, Criterion};

use mpz_circuits::circuits::AES128;
use mpz_common::executor::test_mt_executor;
use mpz_garble::{config::Role, protocol::deap::DEAPVm, Decode, Execute, Memory};
use mpz_ot::ideal::ot::ideal_ot;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("deap");

    let rt = tokio::runtime::Runtime::new().unwrap();
    group.bench_function("aes", |b| {
        b.to_async(&rt).iter(|| async {
            let (mut leader_exec, mut follower_exec) = test_mt_executor(8);

            let (leader_ot_send, follower_ot_recv) = ideal_ot();
            let (follower_ot_send, leader_ot_recv) = ideal_ot();

            let key = [0u8; 16];
            let msg = [0u8; 16];

            let leader_fut = {
                async move {
                    let leader_ctx = leader_exec.new_thread().await.unwrap();

                    let mut leader_vm = DEAPVm::new(
                        Role::Leader,
                        [42u8; 32],
                        leader_ctx,
                        leader_ot_send,
                        leader_ot_recv,
                    );

                    let key_ref = leader_vm.new_private_input::<[u8; 16]>("key").unwrap();
                    let msg_ref = leader_vm.new_private_input::<[u8; 16]>("msg").unwrap();
                    let ciphertext_ref = leader_vm.new_output::<[u8; 16]>("ciphertext").unwrap();

                    leader_vm.assign(&key_ref, key).unwrap();
                    leader_vm.assign(&msg_ref, msg).unwrap();

                    leader_vm
                        .execute(
                            AES128.clone(),
                            &[key_ref.clone(), msg_ref],
                            &[ciphertext_ref.clone()],
                        )
                        .await
                        .unwrap();

                    leader_vm.decode(&[ciphertext_ref]).await.unwrap();

                    leader_vm.finalize().await.unwrap();
                }
            };

            let follower_fut = {
                async move {
                    let follower_ctx = follower_exec.new_thread().await.unwrap();

                    let mut follower_vm = DEAPVm::new(
                        Role::Follower,
                        [69u8; 32],
                        follower_ctx,
                        follower_ot_send,
                        follower_ot_recv,
                    );

                    let key_ref = follower_vm.new_blind_input::<[u8; 16]>("key").unwrap();
                    let msg_ref = follower_vm.new_blind_input::<[u8; 16]>("msg").unwrap();
                    let ciphertext_ref = follower_vm.new_output::<[u8; 16]>("ciphertext").unwrap();

                    follower_vm
                        .execute(
                            AES128.clone(),
                            &[key_ref.clone(), msg_ref],
                            &[ciphertext_ref.clone()],
                        )
                        .await
                        .unwrap();

                    follower_vm.decode(&[ciphertext_ref]).await.unwrap();

                    follower_vm.finalize().await.unwrap();
                }
            };

            futures::join!(leader_fut, follower_fut);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
