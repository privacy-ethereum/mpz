mod evaluator;
mod garbler;
mod auth_gen;
mod auth_eval;

pub(crate) use evaluator::EvaluatorStore;
pub(crate) use garbler::GarblerStore;
pub(crate) use auth_gen::AuthGenStore;
pub(crate) use auth_eval::AuthEvalStore;

#[cfg(test)]
mod tests {
    use mpz_memory_core::{binary::U8, correlated::Delta, Array, MemoryExt, ViewExt};
    use mpz_ot::ideal::cot::ideal_cot;
    use mpz_ot_core::ideal::cot::IdealCOT;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use mpz_common::context::test_st_context;
    use mpz_common::Flush;


    use super::*;

    #[tokio::test]
    async fn test_store_decode() {
        let mut rng = StdRng::seed_from_u64(0);
        let (mut ctx_a, mut ctx_b) = test_st_context(8);

        let delta = Delta::random(&mut rng);
        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let mut gb = GarblerStore::new(rng.random(), delta, cot_send);
        let mut ev = EvaluatorStore::new(cot_recv);

        let val_a = [0u8; 16];
        let val_b = [42u8; 16];
        let val_c = [69u8; 16];

        let ref_a_gb: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_public(ref_a_gb).unwrap();
        let ref_b_gb: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_private(ref_b_gb).unwrap();
        let ref_c_gb: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_blind(ref_c_gb).unwrap();

        let ref_a_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_public(ref_a_ev).unwrap();
        let ref_b_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_blind(ref_b_ev).unwrap();
        let ref_c_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_private(ref_c_ev).unwrap();

        gb.assign(ref_a_gb, val_a).unwrap();
        gb.assign(ref_b_gb, val_b).unwrap();

        ev.assign(ref_a_ev, val_a).unwrap();
        ev.assign(ref_c_ev, val_c).unwrap();

        gb.commit(ref_a_gb).unwrap();
        gb.commit(ref_b_gb).unwrap();
        gb.commit(ref_c_gb).unwrap();

        ev.commit(ref_a_ev).unwrap();
        ev.commit(ref_b_ev).unwrap();
        ev.commit(ref_c_ev).unwrap();

        let mut fut_a_gb = gb.decode(ref_a_gb).unwrap();
        let mut fut_b_gb = gb.decode(ref_b_gb).unwrap();
        let mut fut_c_gb = gb.decode(ref_c_gb).unwrap();

        let mut fut_a_ev = ev.decode(ref_a_ev).unwrap();
        let mut fut_b_ev = ev.decode(ref_b_ev).unwrap();
        let mut fut_c_ev = ev.decode(ref_c_ev).unwrap();

        tokio::join!(
            async {
                gb.flush(&mut ctx_a).await.unwrap();
            },
            async {
                ev.flush(&mut ctx_b).await.unwrap();
            }
        );

        let (val_a_gb, val_b_gb, val_c_gb) = (
            fut_a_gb.try_recv().unwrap().unwrap(),
            fut_b_gb.try_recv().unwrap().unwrap(),
            fut_c_gb.try_recv().unwrap().unwrap(),
        );

        let (val_a_ev, val_b_ev, val_c_ev) = (
            fut_a_ev.try_recv().unwrap().unwrap(),
            fut_b_ev.try_recv().unwrap().unwrap(),
            fut_c_ev.try_recv().unwrap().unwrap(),
        );

        assert_eq!(val_a_gb, val_a_ev);
        assert_eq!(val_b_gb, val_b_ev);
        assert_eq!(val_c_gb, val_c_ev);
        assert_eq!(val_a_gb, val_a);
        assert_eq!(val_b_gb, val_b);
        assert_eq!(val_c_gb, val_c);
    }

    #[tokio::test]
    // TODO: handle public inputs - same as private inputs but auto decoded (so still requires auth bits)
    async fn test_auth_store_decode() {
        let mut rng = StdRng::seed_from_u64(0);
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let delta_a = Delta::random(&mut rng).set_lsb(true);
        let delta_b = Delta::random(&mut rng).set_lsb(false);
        let (cot_gen_send, cot_eval_recv) = ideal_cot(delta_a.into_inner());
        let (cot_eval_send, cot_gen_recv) = ideal_cot(delta_b.into_inner());
        let mut gb = AuthGenStore::new(rng.random(), delta_a, cot_gen_send, cot_gen_recv);
        let mut ev = AuthEvalStore::new(rng.random(), delta_b, cot_eval_send, cot_eval_recv);

        // let val_a = [0u8; 16];
        let val_b = [42u8; 16];
        let val_c = [69u8; 16];

        // let ref_a_gen: Array<U8, 16> = gen.alloc().unwrap();
        // gen.mark_public(ref_a_gen).unwrap();
        let ref_b_gen: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_private(ref_b_gen).unwrap();
        let ref_c_gen: Array<U8, 16> = gb.alloc().unwrap();
        gb.mark_blind(ref_c_gen).unwrap();

        // let ref_a_ev: Array<U8, 16> = ev.alloc().unwrap();
        // ev.mark_public(ref_a_ev).unwrap();
        let ref_b_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_blind(ref_b_ev).unwrap();
        let ref_c_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_private(ref_c_ev).unwrap();

        // gen.assign(ref_a_gen, val_a).unwrap();
        gb.assign(ref_b_gen, val_b).unwrap();

        // ev.assign(ref_a_ev, val_a).unwrap();
        ev.assign(ref_c_ev, val_c).unwrap();

        // gen.commit(ref_a_gen).unwrap();
        gb.commit(ref_b_gen).unwrap();
        gb.commit(ref_c_gen).unwrap();

        // ev.commit(ref_a_ev).unwrap();
        ev.commit(ref_b_ev).unwrap();
        ev.commit(ref_c_ev).unwrap();

        // let mut fut_a_gen = gen.decode(ref_a_gen).unwrap();
        let mut fut_b_gen = gb.decode(ref_b_gen).unwrap();
        let mut fut_c_gen = gb.decode(ref_c_gen).unwrap();

        // let mut fut_a_ev = ev.decode(ref_a_ev).unwrap();
        let mut fut_b_ev = ev.decode(ref_b_ev).unwrap();
        let mut fut_c_ev = ev.decode(ref_c_ev).unwrap();

        tokio::join!(
            async {
                gb.flush(&mut ctx_a).await.unwrap();
            },
            async {
                ev.flush(&mut ctx_b).await.unwrap();
            }
        );

        // let val_a_gen = fut_a_gen.try_recv().unwrap().unwrap();
        // let val_a_ev = fut_a_ev.try_recv().unwrap().unwrap();
        let val_b_gen = fut_b_gen.try_recv().unwrap().unwrap();
        let val_b_ev = fut_b_ev.try_recv().unwrap().unwrap();
        let val_c_gen = fut_c_gen.try_recv().unwrap().unwrap();
        let val_c_ev = fut_c_ev.try_recv().unwrap().unwrap();

        // assert_eq!(val_a_gen, val_a_ev);
        assert_eq!(val_b_gen, val_b_ev);
        assert_eq!(val_c_gen, val_c_ev);
        // assert_eq!(val_a_gen, val_a);
        assert_eq!(val_b_gen, val_b);
        assert_eq!(val_c_gen, val_c);
    }
}
