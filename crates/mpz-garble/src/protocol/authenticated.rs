//! Authenticated garbling protocol.

mod auth_eval;
mod auth_gen;

pub use auth_eval::AuthEval;
pub use auth_gen::AuthGen;


#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_common::context::test_st_context;
    use mpz_memory_core::{
        Array, MemoryExt, ViewExt,
        binary::{Binary, U8},
        correlated::Delta,
    };
    use mpz_ot::ideal::cot::{IdealCOTReceiver, IdealCOTSender, ideal_cot};
    use mpz_vm_core::{Call, CallableExt, Execute, Vm};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    #[test]
    fn test_semihonest_is_vm() {
        fn is_vm<T: Vm<Binary>>() {}
        is_vm::<AuthGen<IdealCOTSender, IdealCOTReceiver>>();
        is_vm::<AuthEval<IdealCOTSender, IdealCOTReceiver>>();
    }

    #[tokio::test]
    async fn test_authenticated() {
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

        assert_eq!(gen_out, ev_out);
    }

    #[tokio::test]
    async fn test_semihonest_nothing_to_do() {
        let mut rng = StdRng::seed_from_u64(0);
        
        let delta_a = Delta::random(&mut rng).set_lsb(true);
        let delta_b = Delta::random(&mut rng).set_lsb(false);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (cot_gen_send, cot_eval_recv) = ideal_cot(delta_a.into_inner());
        let (cot_eval_send, cot_gen_recv) = ideal_cot(delta_b.into_inner());

        let mut gb = AuthGen::new([0u8; 16], delta_a, cot_gen_send, cot_gen_recv);
        let mut ev = AuthEval::new([0u8; 16], delta_b, cot_eval_send, cot_eval_recv);

        gb.flush(&mut ctx_a).await.unwrap();
        ev.flush(&mut ctx_b).await.unwrap();
    }

    // #[tokio::test]
    // async fn test_semihonest_preprocess() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let delta = Delta::random(&mut rng);

    //     let (mut ctx_a, mut ctx_b) = test_st_context(8);
    //     let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

    //     let mut gb = Garbler::new(cot_send, [0u8; 16], delta);
    //     let mut ev = Evaluator::new(cot_recv);

    //     let (gen_out, ev_out) = futures::join!(
    //         async {
    //             let key: Array<U8, 16> = gb.alloc().unwrap();
    //             let msg: Array<U8, 16> = gb.alloc().unwrap();

    //             gb.mark_private(key).unwrap();
    //             gb.mark_blind(msg).unwrap();

    //             let output: Array<U8, 16> = gb
    //                 .call(
    //                     Call::builder(AES128.clone())
    //                         .arg(key)
    //                         .arg(msg)
    //                         .build()
    //                         .unwrap(),
    //                 )
    //                 .unwrap();

    //             // Chain the AES calls.
    //             let ciphertext: Array<U8, 16> = gb
    //                 .call(
    //                     Call::builder(AES128.clone())
    //                         .arg(key)
    //                         .arg(output)
    //                         .build()
    //                         .unwrap(),
    //                 )
    //                 .unwrap();

    //             let mut ciphertext = gb.decode(ciphertext).unwrap();

    //             assert!(gb.wants_preprocess());
    //             gb.preprocess(&mut ctx_a).await.unwrap();

    //             gb.assign(key, [0u8; 16]).unwrap();
    //             gb.commit(key).unwrap();
    //             gb.commit(msg).unwrap();

    //             gb.execute_all(&mut ctx_a).await.unwrap();
    //             ciphertext.try_recv().unwrap().unwrap()
    //         },
    //         async {
    //             let key: Array<U8, 16> = ev.alloc().unwrap();
    //             let msg: Array<U8, 16> = ev.alloc().unwrap();

    //             ev.mark_blind(key).unwrap();
    //             ev.mark_private(msg).unwrap();

    //             let output: Array<U8, 16> = ev
    //                 .call(
    //                     Call::builder(AES128.clone())
    //                         .arg(key)
    //                         .arg(msg)
    //                         .build()
    //                         .unwrap(),
    //                 )
    //                 .unwrap();

    //             // Chain the AES calls.
    //             let ciphertext: Array<U8, 16> = ev
    //                 .call(
    //                     Call::builder(AES128.clone())
    //                         .arg(key)
    //                         .arg(output)
    //                         .build()
    //                         .unwrap(),
    //                 )
    //                 .unwrap();

    //             let mut ciphertext = ev.decode(ciphertext).unwrap();

    //             assert!(ev.wants_preprocess());
    //             ev.preprocess(&mut ctx_b).await.unwrap();

    //             ev.assign(msg, [42u8; 16]).unwrap();
    //             ev.commit(key).unwrap();
    //             ev.commit(msg).unwrap();

    //             ev.execute_all(&mut ctx_b).await.unwrap();
    //             ciphertext.try_recv().unwrap().unwrap()
    //         }
    //     );

    //     assert_eq!(gen_out, ev_out);
    // }
}
