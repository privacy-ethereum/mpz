use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mpz_common::executor::test_st_executor;
use mpz_core::Block;
use mpz_ot::{
    chou_orlandi::{Receiver, Sender},
    OTReceiver, OTSender, OTSetup,
};

fn chou_orlandi(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("chou_orlandi");
    for n in [128, 256, 1024] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let msgs = vec![[Block::ONES; 2]; n];
            let choices = vec![false; n];
            b.to_async(&rt).iter(|| async {
                let (mut sender_ctx, mut receiver_ctx) = test_st_executor(8);

                let mut sender = Sender::default();
                let mut receiver = Receiver::default();

                futures::try_join!(
                    sender.setup(&mut sender_ctx),
                    receiver.setup(&mut receiver_ctx)
                )
                .unwrap();

                let (_, received) = futures::try_join!(
                    sender.send(&mut sender_ctx, &msgs),
                    receiver.receive(&mut receiver_ctx, &choices)
                )
                .unwrap();

                black_box(received)
            })
        });
    }
}

criterion_group! {
    name = chou_orlandi_benches;
    config = Criterion::default().sample_size(50);
    targets = chou_orlandi
}

criterion_main!(chou_orlandi_benches);
