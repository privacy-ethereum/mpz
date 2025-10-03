//! Copies of Evaluator and Garbler with minimal modifications to remove all
//! cryptography operations.
//!
//! Places in the code which were changed are marked with // CHANGED

mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

// The tests make sure that the mock is consistent with the real impl.
#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_common::{Flush, context::test_st_context};
    use mpz_core::Block;
    use mpz_memory_core::{
        Array, MemoryExt, ViewExt,
        binary::{Binary, U8},
        correlated::Delta,
    };
    use mpz_ot::{
        cot::{COTReceiver, COTSender},
        ideal::cot::{IdealCOTReceiver, IdealCOTSender, ideal_cot},
    };
    use mpz_vm_core::{Call, CallableExt, Execute, Vm};
    use rand::{SeedableRng, rngs::StdRng};

    use crate::protocol::semihonest::{
        Evaluator as RealEvaluator, Garbler as RealGarbler,
        mock::{Evaluator, Garbler},
    };

    #[ignore = "verifies mock matches real implementation"]
    #[tokio::test]
    async fn test_semihonest() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gb = RealGarbler::new(cot_send, [0u8; 16], delta);
        let mut ev = RealEvaluator::new(cot_recv);

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

        assert_eq!(gen_out, ev_out);

        let real_gen_out = gen_out;

        // --------- Same as above but with a mock.

        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

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

        assert_eq!(gen_out, ev_out);

        assert_eq!(real_gen_out, gen_out);
    }

    #[ignore = "verifies mock matches real implementation"]
    #[tokio::test]
    async fn test_semihonest_nothing_to_do() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gb = RealGarbler::new(cot_send, [0u8; 16], delta);
        let mut ev = RealEvaluator::new(cot_recv);

        gb.flush(&mut ctx_a).await.unwrap();
        ev.flush(&mut ctx_b).await.unwrap();

        // --------- Same as above but with a mock.

        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        gb.flush(&mut ctx_a).await.unwrap();
        ev.flush(&mut ctx_b).await.unwrap();
    }

    #[ignore = "verifies mock matches real implementation"]
    #[tokio::test]
    async fn test_semihonest_preprocess() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gb = RealGarbler::new(cot_send, [0u8; 16], delta);
        let mut ev = RealEvaluator::new(cot_recv);

        let (gen_out, ev_out) = futures::join!(
            async {
                let key: Array<U8, 16> = gb.alloc().unwrap();
                let msg: Array<U8, 16> = gb.alloc().unwrap();

                gb.mark_private(key).unwrap();
                gb.mark_blind(msg).unwrap();

                let output: Array<U8, 16> = gb
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                // Chain the AES calls.
                let ciphertext: Array<U8, 16> = gb
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(output)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = gb.decode(ciphertext).unwrap();

                assert!(gb.wants_preprocess());
                gb.preprocess(&mut ctx_a).await.unwrap();

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

                let output: Array<U8, 16> = ev
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                // Chain the AES calls.
                let ciphertext: Array<U8, 16> = ev
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(output)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = ev.decode(ciphertext).unwrap();

                assert!(ev.wants_preprocess());
                ev.preprocess(&mut ctx_b).await.unwrap();

                ev.assign(msg, [42u8; 16]).unwrap();
                ev.commit(key).unwrap();
                ev.commit(msg).unwrap();

                ev.execute_all(&mut ctx_b).await.unwrap();
                ciphertext.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(gen_out, ev_out);

        let real_gen_out = gen_out;

        // --------- Same as above but with a mock.

        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        let (gb, ev) = futures::join!(
            async {
                let key: Array<U8, 16> = gb.alloc().unwrap();
                let msg: Array<U8, 16> = gb.alloc().unwrap();

                gb.mark_private(key).unwrap();
                gb.mark_blind(msg).unwrap();

                let output: Array<U8, 16> = gb
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                // Chain the AES calls.
                let ciphertext: Array<U8, 16> = gb
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(output)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = gb.decode(ciphertext).unwrap();

                assert!(gb.wants_preprocess());
                gb.preprocess(&mut ctx_a).await.unwrap();
                (gb, key, msg, ciphertext)

                // gb.assign(key, [0u8; 16]).unwrap();
                // gb.commit(key).unwrap();
                // gb.commit(msg).unwrap();

                // gb.execute_all(&mut ctx_a).await.unwrap();
                //ciphertext.try_recv().unwrap().unwrap()
            },
            async {
                let key: Array<U8, 16> = ev.alloc().unwrap();
                let msg: Array<U8, 16> = ev.alloc().unwrap();

                ev.mark_blind(key).unwrap();
                ev.mark_private(msg).unwrap();

                let output: Array<U8, 16> = ev
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                // Chain the AES calls.
                let ciphertext: Array<U8, 16> = ev
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(output)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = ev.decode(ciphertext).unwrap();

                assert!(ev.wants_preprocess());
                ev.preprocess(&mut ctx_b).await.unwrap();

                (ev, key, msg, ciphertext)

                // ev.assign(msg, [42u8; 16]).unwrap();
                // ev.commit(key).unwrap();
                // ev.commit(msg).unwrap();

                // ev.execute_all(&mut ctx_b).await.unwrap();
                //ciphertext.try_recv().unwrap().unwrap()
            }
        );

        // TODO: there is  bug in IdealOT due to which we must not make any VM calls
        // on either side until both parties finish preprocessing.

        let (gen_out, ev_out) = futures::join!(
            async {
                let (mut gb, key, msg, mut ciphertext) = gb;
                gb.assign(key, [0u8; 16]).unwrap();
                gb.commit(key).unwrap();
                gb.commit(msg).unwrap();

                gb.execute_all(&mut ctx_a).await.unwrap();
                ciphertext.try_recv().unwrap().unwrap()
            },
            async {
                let (mut ev, key, msg, mut ciphertext) = ev;

                ev.assign(msg, [42u8; 16]).unwrap();
                ev.commit(key).unwrap();
                ev.commit(msg).unwrap();

                ev.execute_all(&mut ctx_b).await.unwrap();
                ciphertext.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(gen_out, ev_out);
        assert_eq!(gen_out, real_gen_out);
    }

    #[ignore = "verifies mock matches real implementation"]
    #[tokio::test]
    // Tests that OT is flushed when `preprocess` is called.
    async fn test_semihonest_concurrent_flush() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut cot_send, mut cot_recv) = ideal_cot(delta.into_inner());

        // Put the sender and the receiver in a state where they want to flush.
        drop(cot_send.queue_send_cot(&[Block::default()]).unwrap());
        drop(cot_recv.queue_recv_cot(&[true]).unwrap());
        assert!(cot_send.wants_flush());
        assert!(cot_recv.wants_flush());

        let mut gb = RealGarbler::new(cot_send, [0u8; 16], delta);
        let mut ev = RealEvaluator::new(cot_recv);

        let (_, _) = futures::join!(
            async {
                gb.preprocess(&mut ctx_a).await.unwrap();
            },
            async {
                ev.preprocess(&mut ctx_b).await.unwrap();
            }
        );

        let gb_cot = gb.store().try_lock().unwrap().acquire_cot();
        let ev_cot = ev.store().try_lock().unwrap().acquire_cot();
        assert!(!gb_cot.wants_flush());
        assert!(!ev_cot.wants_flush());

        // --------- Same as above but with a mock.

        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut cot_send, mut cot_recv) = ideal_cot(delta.into_inner());

        // Put the sender and the receiver in a state where they want to flush.
        drop(cot_send.queue_send_cot(&[Block::default()]).unwrap());
        drop(cot_recv.queue_recv_cot(&[true]).unwrap());
        assert!(cot_send.wants_flush());
        assert!(cot_recv.wants_flush());

        let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        let (_, _) = futures::join!(
            async {
                gb.preprocess(&mut ctx_a).await.unwrap();
            },
            async {
                ev.preprocess(&mut ctx_b).await.unwrap();
            }
        );

        let gb_cot = gb.store().try_lock().unwrap().acquire_cot();
        let ev_cot = ev.store().try_lock().unwrap().acquire_cot();
        assert!(!gb_cot.wants_flush());
        assert!(!ev_cot.wants_flush());
    }
}
