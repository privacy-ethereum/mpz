mod prover;
mod verifier;

pub use prover::Prover;
pub use verifier::Verifier;

#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_common::executor::test_st_executor;
    use mpz_ot::ideal::rcot::{ideal_rcot, IdealRCOTReceiver, IdealRCOTSender};
    use mpz_vm_core::{
        memory::{
            binary::{Binary, U8},
            correlated::Delta,
            Array,
        },
        prelude::*,
        Call, Vm,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_zk_is_vm() {
        fn is_vm<T: Vm<Binary>>() {}
        is_vm::<Prover<IdealRCOTReceiver>>();
        is_vm::<Verifier<IdealRCOTSender>>();
    }

    #[tokio::test]
    async fn test_zk() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let (mut ctx_p, mut ctx_v) = test_st_executor(8);

        let (ot_send, ot_recv) = ideal_rcot(rng.gen(), delta.into_inner());

        let mut prover = Prover::new(ot_recv);
        let mut verifier = Verifier::new(delta, ot_send);

        let (ciphertext_p, ciphertext_v) = futures::join!(
            {
                let key: Array<U8, 16> = prover.alloc().unwrap();
                let msg: Array<U8, 16> = prover.alloc().unwrap();

                let ciphertext: Array<U8, 16> = prover
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                    .unwrap();

                prover.mark_private(key).unwrap();
                prover.mark_public(msg).unwrap();

                prover.assign(key, [0u8; 16]).unwrap();
                prover.assign(msg, [42u8; 16]).unwrap();

                prover.commit(key).unwrap();
                prover.commit(msg).unwrap();

                let mut ciphertext = prover.decode(ciphertext).unwrap();

                async move {
                    prover.flush(&mut ctx_p).await.unwrap();
                    prover.execute(&mut ctx_p).await.unwrap();
                    prover.flush(&mut ctx_p).await.unwrap();

                    ciphertext.try_recv().unwrap().unwrap()
                }
            },
            {
                let key: Array<U8, 16> = verifier.alloc().unwrap();
                let msg: Array<U8, 16> = verifier.alloc().unwrap();

                let ciphertext: Array<U8, 16> = verifier
                    .call(Call::new(AES128.clone()).arg(key).arg(msg).build().unwrap())
                    .unwrap();

                verifier.mark_blind(key).unwrap();
                verifier.mark_public(msg).unwrap();

                verifier.assign(msg, [42u8; 16]).unwrap();

                verifier.commit(key).unwrap();
                verifier.commit(msg).unwrap();

                let mut ciphertext = verifier.decode(ciphertext).unwrap();

                async move {
                    verifier.flush(&mut ctx_v).await.unwrap();
                    verifier.execute(&mut ctx_v).await.unwrap();
                    verifier.flush(&mut ctx_v).await.unwrap();

                    ciphertext.try_recv().unwrap().unwrap()
                }
            }
        );

        assert_eq!(ciphertext_p, ciphertext_v);
    }
}
