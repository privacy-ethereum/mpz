use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use itybity::ToBits;
use mpz_core::Block;
use mpz_ot_core::{
    chou_orlandi, kos,
    ot::{OTReceiver, OTSender},
    rcot::{RCOTReceiver, RCOTSender},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

fn chou_orlandi(c: &mut Criterion) {
    let mut group = c.benchmark_group("chou_orlandi");
    for n in [128, 256, 1024] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let msgs = vec![[Block::ONES; 2]; n];
            let mut rng = ChaCha12Rng::seed_from_u64(0);
            let choices = (0..n).map(|_| rng.gen()).collect::<Vec<bool>>();
            b.iter(|| {
                let sender = chou_orlandi::Sender::default();
                let receiver = chou_orlandi::Receiver::default();

                let (sender_setup, mut sender) = sender.setup();
                let mut receiver = receiver.setup(sender_setup);

                let sender_output = sender.queue_send_ot(&msgs).unwrap();
                let receiver_output = receiver.queue_recv_ot(&choices).unwrap();

                let receiver_payload = receiver.choose();
                let sender_payload = sender.send(receiver_payload).unwrap();
                receiver.receive(sender_payload).unwrap();

                black_box((sender_output, receiver_output))
            })
        });
    }
}

fn kos(c: &mut Criterion) {
    let mut group = c.benchmark_group("kos");
    for n in [1024, 262144] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let mut rng = ChaCha12Rng::seed_from_u64(0);
            let delta = Block::random(&mut rng);
            let chi_seed = Block::random(&mut rng);

            let receiver_seeds: [[Block; 2]; 128] = std::array::from_fn(|_| [rng.gen(), rng.gen()]);
            let sender_seeds: [Block; 128] = delta
                .iter_lsb0()
                .zip(receiver_seeds)
                .map(|(b, seeds)| if b { seeds[1] } else { seeds[0] })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            b.iter(|| {
                let sender = kos::Sender::new(kos::SenderConfig::default(), delta);
                let receiver = kos::Receiver::new(kos::ReceiverConfig::default());

                let mut sender = sender.setup(sender_seeds);
                let mut receiver = receiver.setup(receiver_seeds);

                sender.alloc(n).unwrap();
                receiver.alloc(n).unwrap();

                while receiver.wants_extend() {
                    let extend = receiver.extend().unwrap();
                    sender.extend(extend).unwrap();
                }

                let check = receiver.check(chi_seed).unwrap();
                sender.check(chi_seed, check).unwrap();

                black_box((sender, receiver));
            })
        });
    }
}

criterion_group! {
    name = chou_orlandi_benches;
    config = Criterion::default().sample_size(50);
    targets = chou_orlandi
}

criterion_group! {
    name = kos_benches;
    config = Criterion::default().sample_size(50);
    targets = kos
}

criterion_main!(chou_orlandi_benches, kos_benches);
