//! [Two Halves Make a Whole \[ZRE15\]](https://eprint.iacr.org/2014/756) protocol with semi-honest security.

mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;
use mpz_memory_core::Slice;
use mpz_vm_core::Call;
use rangeset::{Disjoint, RangeSet};

/// Takes those calls from the `call_stack` which are ready for preprocessing.
fn take_preprocess_calls(call_stack: &mut Vec<(Call, Slice)>) -> Vec<(Call, Slice)> {
    let mut idx_outputs = RangeSet::default();
    call_stack
        // Extract calls which have no dependencies on other prior calls.
        .extract_if(.., |(call, output)| {
            if call
                .inputs()
                .iter()
                .all(|input| input.to_range().is_disjoint(&idx_outputs))
            {
                idx_outputs |= output.to_range();
                true
            } else {
                idx_outputs |= output.to_range();
                false
            }
        })
        .collect()
}

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

    use super::*;

    #[test]
    fn test_semihonest_is_vm() {
        fn is_vm<T: Vm<Binary>>() {}
        is_vm::<Garbler<IdealCOTSender>>();
        is_vm::<Evaluator<IdealCOTReceiver>>();
    }

    #[tokio::test]
    async fn test_semihonest() {
        let mut rng = StdRng::seed_from_u64(0);
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
    }

    #[tokio::test]
    async fn test_semihonest_nothing_to_do() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        gb.flush(&mut ctx_a).await.unwrap();
        ev.flush(&mut ctx_b).await.unwrap();
    }

    #[tokio::test]
    async fn test_semihonest_preprocess() {
        let mut rng = StdRng::seed_from_u64(0);
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
    }

    #[tokio::test]
    // Tests that OT is flushed when `preprocess` is called.
    async fn test_semihonest_concurrent_flush() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut cot_send, mut cot_recv) = ideal_cot(delta.into_inner());

        // Put the sender and the receiver in a state where they want to flush.
        let _ = cot_send
            .queue_send_cot(&[Block::default()])
            .unwrap()
            .await
            .unwrap();
        let _ = cot_recv.queue_recv_cot(&[true]).unwrap().await.unwrap();
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
