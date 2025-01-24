//! [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) protocol with semi-honest security.

mod evaluator;
mod generator;

pub use evaluator::Evaluator;
pub use generator::Generator;

#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_common::context::test_st_context;
    use mpz_memory_core::{
        binary::{Binary, U8},
        correlated::Delta,
        Array, MemoryExt, ViewExt,
    };
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_vm_core::{Call, CallableExt, Execute, Vm};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn test_semihonest_is_vm() {
        fn is_vm<T: Vm<Binary>>() {}
        is_vm::<Generator<IdealCOTSender>>();
        is_vm::<Evaluator<IdealCOTReceiver>>();
    }

    #[tokio::test]
    async fn test_semihonest() {
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

                let mut ciphertext = gen.decode(ciphertext).unwrap();

                gen.assign(key, [0u8; 16]).unwrap();
                gen.commit(key).unwrap();
                gen.commit(msg).unwrap();

                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();

                ciphertext.try_recv().unwrap().unwrap()
            },
            async {
                let key: Array<U8, 16> = ev.alloc().unwrap();
                let msg: Array<U8, 16> = ev.alloc().unwrap();

                ev.mark_blind(key).unwrap();
                ev.mark_private(msg).unwrap();

                let ciphertext: Array<U8, 16> = ev
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                    .unwrap();

                let mut ciphertext = ev.decode(ciphertext).unwrap();

                ev.assign(msg, [42u8; 16]).unwrap();
                ev.commit(key).unwrap();
                ev.commit(msg).unwrap();

                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();

                ciphertext.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(gen_out, ev_out);
    }

    #[tokio::test]
    async fn test_semihonest_nothing_to_do() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gen = Generator::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        gen.flush(&mut ctx_a).await.unwrap();
        ev.flush(&mut ctx_b).await.unwrap();
    }

    #[tokio::test]
    async fn test_semihonest_preprocess() {
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

                let output: Array<U8, 16> = gen
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                    .unwrap();

                // Chain the AES calls.
                let ciphertext: Array<U8, 16> = gen
                    .call(
                        Call::new(AES128.clone())
                            .arg(key)
                            .arg(output)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = gen.decode(ciphertext).unwrap();

                gen.preprocess(&mut ctx_a).await.unwrap();

                gen.assign(key, [0u8; 16]).unwrap();
                gen.commit(key).unwrap();
                gen.commit(msg).unwrap();

                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();

                ciphertext.try_recv().unwrap().unwrap()
            },
            async {
                let key: Array<U8, 16> = ev.alloc().unwrap();
                let msg: Array<U8, 16> = ev.alloc().unwrap();

                ev.mark_blind(key).unwrap();
                ev.mark_private(msg).unwrap();

                let output: Array<U8, 16> = ev
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                    .unwrap();

                // Chain the AES calls.
                let ciphertext: Array<U8, 16> = ev
                    .call(
                        Call::new(AES128.clone())
                            .arg(key)
                            .arg(output)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = ev.decode(ciphertext).unwrap();

                ev.preprocess(&mut ctx_b).await.unwrap();

                ev.assign(msg, [42u8; 16]).unwrap();
                ev.commit(key).unwrap();
                ev.commit(msg).unwrap();

                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();

                ciphertext.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(gen_out, ev_out);
    }
}
