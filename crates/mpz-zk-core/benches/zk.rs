use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use mpz_circuits::circuits::AES128;
use mpz_memory_core::correlated::{Delta, Key, Mac};
use mpz_ot_core::{
    ideal::rcot::IdealRCOT,
    rcot::{RCOTReceiverOutput, RCOTSenderOutput},
};
use mpz_zk_core::{Prover, Verifier};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("zk-core");

    group.throughput(Throughput::Bytes(16));
    group.bench_function("aes128", |b| {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut rcot = IdealRCOT::new(rng.gen(), delta.into_inner());

        rcot.alloc(AES128.input_len());
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { mut keys, .. },
            RCOTReceiverOutput {
                msgs: mut macs,
                choices,
                ..
            },
        ) = rcot.transfer(AES128.input_len()).unwrap();
        keys.iter_mut().for_each(|key| key.set_lsb(false));
        macs.iter_mut()
            .zip(choices)
            .for_each(|(mac, choice)| mac.set_lsb(choice));

        let input_keys = Key::from_blocks(keys);
        let input_macs = Mac::from_blocks(macs);

        rcot.alloc(AES128.and_count());
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { keys, .. },
            RCOTReceiverOutput {
                choices: gate_masks,
                msgs: macs,
                ..
            },
        ) = rcot.transfer(AES128.and_count()).unwrap();
        let gate_keys = Key::from_blocks(keys);
        let gate_macs = Mac::from_blocks(macs);

        rcot.alloc(128);
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput {
                keys: svole_keys, ..
            },
            RCOTReceiverOutput {
                choices: svole_choices,
                msgs: svole_ev,
                ..
            },
        ) = rcot.transfer(128).unwrap();

        let mut prover = Prover::default();
        let mut verifier = Verifier::new(delta);

        b.iter(|| {
            let mut prover_execute = prover
                .execute(AES128.clone(), &input_macs, &gate_masks, &gate_macs)
                .unwrap();
            let mut verifier_execute = verifier
                .execute(AES128.clone(), &input_keys, &gate_keys)
                .unwrap();

            let mut verifier_consumer = verifier_execute.consumer();
            for adjust in prover_execute.iter() {
                verifier_consumer.next(adjust);
            }

            let output_macs = prover_execute.finish().unwrap();
            let output_keys = verifier_execute.finish().unwrap();

            let uv = prover.check(&svole_choices, &svole_ev).unwrap();
            verifier.check(&svole_keys, uv).unwrap();

            black_box((output_macs, output_keys))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
