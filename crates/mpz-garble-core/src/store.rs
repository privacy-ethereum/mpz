//! Memory stores.

mod evaluator;
mod generator;

pub use evaluator::{EvaluatorStore, EvaluatorStoreError};
pub use generator::{GeneratorStore, GeneratorStoreError};

use blake3::Hash;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::correlated::{Mac, MacCommitment};
use serde::{Deserialize, Serialize};

use crate::view::FlushView;

/// Flush message sent by the generator.
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "validation::GeneratorFlushUnchecked")]
pub struct GeneratorFlush {
    /// Flush view.
    view: FlushView,
    /// MACs sent directly to the evaluator.
    macs: Vec<Mac>,
    /// Key bits for decoding.
    key_bits: BitVec,
    /// MAC commitments sent for decoding.
    mac_commitments: Vec<MacCommitment>,
}

/// Flush message sent by the evaluator.
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "validation::EvaluatorFlushUnchecked")]
pub struct EvaluatorFlush {
    /// Flush view.
    view: FlushView,
    /// Proof of MACs for decoding.
    mac_proof: Option<MacProof>,
}

/// MAC proof sent from the evaluator to the generator to prove
/// the output of a circuit.
#[derive(Debug, Serialize, Deserialize)]
pub struct MacProof {
    bits: BitVec,
    proof: Hash,
}

mod validation {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub(super) struct GeneratorFlushUnchecked {
        pub view: FlushView,
        pub macs: Vec<Mac>,
        pub key_bits: BitVec,
        pub mac_commitments: Vec<MacCommitment>,
    }

    impl TryFrom<GeneratorFlushUnchecked> for GeneratorFlush {
        type Error = String;

        fn try_from(value: GeneratorFlushUnchecked) -> Result<Self, Self::Error> {
            let GeneratorFlushUnchecked {
                view: idx,
                macs,
                key_bits,
                mac_commitments,
            } = value;

            if idx.macs.len().saturating_sub(idx.ot.len()) != macs.len() {
                return Err("generator sent flush with invalid number of MACs".to_string());
            }

            if idx.decode_info.len() != key_bits.len() {
                return Err("generator sent flush with invalid number of key bits".to_string());
            }

            if mac_commitments.len() != key_bits.len() {
                return Err(
                    "generator sent flush with invalid number of MAC commitments".to_string(),
                );
            }

            Ok(GeneratorFlush {
                view: idx,
                macs,
                key_bits,
                mac_commitments,
            })
        }
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct EvaluatorFlushUnchecked {
        pub view: FlushView,
        pub macs: Option<MacProof>,
    }

    impl TryFrom<EvaluatorFlushUnchecked> for EvaluatorFlush {
        type Error = String;

        fn try_from(value: EvaluatorFlushUnchecked) -> Result<Self, Self::Error> {
            let EvaluatorFlushUnchecked { view: idx, macs } = value;

            if idx.decode.len() != macs.as_ref().map_or(0, |m| m.bits.len()) {
                return Err("evaluator sent flush with invalid number of MACs".to_string());
            }

            Ok(EvaluatorFlush {
                view: idx,
                mac_proof: macs,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use mpz_memory_core::{binary::U8, correlated::Delta, Array, MemoryExt, ViewExt};
    use mpz_ot_core::ideal::cot::IdealCOT;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_store_decode() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let cot = IdealCOT::new(delta.into_inner());

        let mut gen = GeneratorStore::new(rng.gen(), delta, cot.clone());
        let mut ev = EvaluatorStore::new(cot);

        let val_a = [0u8; 16];
        let val_b = [42u8; 16];
        let val_c = [69u8; 16];

        let ref_a_gen: Array<U8, 16> = gen.alloc().unwrap();
        gen.mark_public(ref_a_gen).unwrap();
        let ref_b_gen: Array<U8, 16> = gen.alloc().unwrap();
        gen.mark_private(ref_b_gen).unwrap();
        let ref_c_gen: Array<U8, 16> = gen.alloc().unwrap();
        gen.mark_blind(ref_c_gen).unwrap();

        let ref_a_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_public(ref_a_ev).unwrap();
        let ref_b_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_blind(ref_b_ev).unwrap();
        let ref_c_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_private(ref_c_ev).unwrap();

        gen.assign(ref_a_gen, val_a).unwrap();
        gen.assign(ref_b_gen, val_b).unwrap();

        ev.assign(ref_a_ev, val_a).unwrap();
        ev.assign(ref_c_ev, val_c).unwrap();

        gen.commit(ref_a_gen).unwrap();
        gen.commit(ref_b_gen).unwrap();
        gen.commit(ref_c_gen).unwrap();

        ev.commit(ref_a_ev).unwrap();
        ev.commit(ref_b_ev).unwrap();
        ev.commit(ref_c_ev).unwrap();

        assert!(gen.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gen.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gen.acquire_cot().flush().unwrap();

        gen.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        let mut fut_a_gen = gen.decode(ref_a_gen).unwrap();
        let mut fut_b_gen = gen.decode(ref_b_gen).unwrap();
        let mut fut_c_gen = gen.decode(ref_c_gen).unwrap();

        let mut fut_a_ev = ev.decode(ref_a_ev).unwrap();
        let mut fut_b_ev = ev.decode(ref_b_ev).unwrap();
        let mut fut_c_ev = ev.decode(ref_c_ev).unwrap();

        assert!(gen.wants_flush());
        assert!(ev.wants_flush());

        let gen_flush = gen.send_flush().unwrap();
        let ev_flush = ev.send_flush().unwrap();

        gen.receive_flush(ev_flush).unwrap();
        ev.receive_flush(gen_flush).unwrap();

        let (val_a_gen, val_b_gen, val_c_gen) = (
            fut_a_gen.try_recv().unwrap().unwrap(),
            fut_b_gen.try_recv().unwrap().unwrap(),
            fut_c_gen.try_recv().unwrap().unwrap(),
        );

        let (val_a_ev, val_b_ev, val_c_ev) = (
            fut_a_ev.try_recv().unwrap().unwrap(),
            fut_b_ev.try_recv().unwrap().unwrap(),
            fut_c_ev.try_recv().unwrap().unwrap(),
        );

        assert_eq!(val_a_gen, val_a_ev);
        assert_eq!(val_b_gen, val_b_ev);
        assert_eq!(val_c_gen, val_c_ev);
        assert_eq!(val_a_gen, val_a);
        assert_eq!(val_b_gen, val_b);
        assert_eq!(val_c_gen, val_c);
    }
}
