//! Copies of E and G with minimal modifications to remove all cryptography
//! operations.
//!
//! Places in the code which were changed are marked with // CHANGED

mod evaluator;
mod garbler;

pub use crate::store::mock::{
    evaluator::{EvaluatorStore, EvaluatorStoreError},
    garbler::{GarblerStore, GarblerStoreError},
};

// The tests make sure that the mock is consistent with the real impl.
#[cfg(test)]
mod tests {
    use crate::store::{EvaluatorStore as RealEvaluatorStore, GarblerStore as RealGarblerStore};
    use mpz_core::Block;
    use mpz_memory_core::{
        Array, Memory, MemoryExt, ViewExt,
        binary::{Binary, U8},
        correlated::{Delta, Key},
    };
    use mpz_ot_core::ideal::cot::IdealCOT;
    use mpz_vm_core::Vm;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use super::*;

    #[ignore = "verifies mock matches real implementation"]
    #[test]
    fn test_store_decode() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let cot = IdealCOT::new(delta.into_inner());

        // ---------------- Obtain real impl's outputs.

        let mut gb = RealGarblerStore::new(rng.random(), delta, cot.clone());
        let mut ev = RealEvaluatorStore::new(cot.clone());

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

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.acquire_cot().flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        let mut fut_a_gb = gb.decode(ref_a_gb).unwrap();
        let mut fut_b_gb = gb.decode(ref_b_gb).unwrap();
        let mut fut_c_gb = gb.decode(ref_c_gb).unwrap();

        let mut fut_a_ev = ev.decode(ref_a_ev).unwrap();
        let mut fut_b_ev = ev.decode(ref_b_ev).unwrap();
        let mut fut_c_ev = ev.decode(ref_c_ev).unwrap();

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

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

        let real_val_a_gb = val_a_gb;
        let real_val_b_gb = val_b_gb;
        let real_val_c_gb = val_c_gb;

        // ----------------The same as above but for a mock impl.

        let delta = Delta::random(&mut rng);
        let cot = IdealCOT::new(delta.into_inner());

        let mut gb = GarblerStore::new(rng.random(), delta, cot.clone());
        let mut ev = EvaluatorStore::new(cot);

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

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.acquire_cot().flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        let mut fut_a_gb = gb.decode(ref_a_gb).unwrap();
        let mut fut_b_gb = gb.decode(ref_b_gb).unwrap();
        let mut fut_c_gb = gb.decode(ref_c_gb).unwrap();

        let mut fut_a_ev = ev.decode(ref_a_ev).unwrap();
        let mut fut_b_ev = ev.decode(ref_b_ev).unwrap();
        let mut fut_c_ev = ev.decode(ref_c_ev).unwrap();

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

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

        // Make sure real and mock outputs match.

        assert_eq!(val_a_gb, real_val_a_gb);
        assert_eq!(val_b_gb, real_val_b_gb);
        assert_eq!(val_c_gb, real_val_c_gb);
    }

    // Tests that calling decode on a preprocessed output twice behaves
    // correctly.
    #[ignore = "verifies mock matches real implementation"]
    #[test]
    fn test_store_decode_preprocessed() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let cot = IdealCOT::new(delta.into_inner());

        let mut gb = RealGarblerStore::new(rng.random(), delta, cot.clone());
        let mut ev = RealEvaluatorStore::new(cot);

        let ref_out_gb = gb.alloc_output(16);
        gb.set_output(ref_out_gb, &Key::from_blocks(vec![Block::ZERO; 16]))
            .unwrap();
        std::mem::drop(gb.decode_raw(ref_out_gb).unwrap());

        let ref_out_ev = ev.alloc_output(16);
        ev.mark_output_preprocessed(ref_out_ev).unwrap();
        std::mem::drop(ev.decode_raw(ref_out_ev).unwrap());

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        std::mem::drop(gb.decode_raw(ref_out_gb).unwrap());
        std::mem::drop(ev.decode_raw(ref_out_ev).unwrap());

        // ---------------Same as above but with a mock.

        let delta = Delta::random(&mut rng);
        let cot = IdealCOT::new(delta.into_inner());

        let mut gb = GarblerStore::new(rng.random(), delta, cot.clone());
        let mut ev = EvaluatorStore::new(cot);

        let ref_out_gb = gb.alloc_output(16);
        gb.set_output(ref_out_gb, &Key::from_blocks(vec![Block::ZERO; 16]))
            .unwrap();
        std::mem::drop(gb.decode_raw(ref_out_gb).unwrap());

        let ref_out_ev = ev.alloc_output(16);
        ev.mark_output_preprocessed(ref_out_ev).unwrap();
        std::mem::drop(ev.decode_raw(ref_out_ev).unwrap());

        assert!(gb.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gb.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gb.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        std::mem::drop(gb.decode_raw(ref_out_gb).unwrap());
        std::mem::drop(ev.decode_raw(ref_out_ev).unwrap());

        // There should be nothing to flush, since the decoding info
        // has already been sent in the first flush.
        assert!(!gb.wants_flush() && !ev.wants_flush());
    }
}
