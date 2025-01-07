mod prover;
mod verifier;

pub use prover::{ProverStore, ProverStoreError};
pub use verifier::{VerifierStore, VerifierStoreError};

use blake3::Hash;
use mpz_core::bitvec::BitVec;
use serde::{Deserialize, Serialize};

use crate::view::FlushView;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverFlush {
    view: FlushView,
    adjust: BitVec,
    mac_proof: Option<(BitVec, Hash)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierFlush {
    view: FlushView,
}

#[cfg(test)]
mod tests {
    use mpz_core::bitvec::BitVec;
    use mpz_memory_core::{
        binary::U8,
        correlated::{Delta, Key},
        Array, MemoryExt, ViewExt,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_store() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let mut verifier = VerifierStore::new(delta);
        let mut prover = ProverStore::new();

        let keys = (0..128).map(|_| rng.gen()).collect::<Vec<Key>>();
        let masks = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let macs = keys
            .iter()
            .zip(&masks)
            .map(|(key, bit)| key.auth(*bit, &delta))
            .collect::<Vec<_>>();

        let a_v: Array<U8, 16> = verifier.alloc().unwrap();
        let b_v: Array<U8, 16> = verifier.alloc().unwrap();

        let a_p: Array<U8, 16> = prover.alloc().unwrap();
        let b_p: Array<U8, 16> = prover.alloc().unwrap();

        verifier.mark_public(a_v).unwrap();
        verifier.mark_blind(b_v).unwrap();
        verifier.assign(a_v, [42u8; 16]).unwrap();
        verifier.commit(a_v).unwrap();
        verifier.commit(b_v).unwrap();

        prover.mark_public(a_p).unwrap();
        prover.mark_private(b_p).unwrap();
        prover.assign(a_p, [42u8; 16]).unwrap();
        prover.assign(b_p, [69u8; 16]).unwrap();
        prover.commit(a_p).unwrap();
        prover.commit(b_p).unwrap();

        let mut b_v = verifier.decode(b_v).unwrap();
        let _ = prover.decode(b_p).unwrap();

        assert!(verifier.wants_keys());
        assert!(prover.wants_macs());

        assert_eq!(verifier.key_count(), prover.mac_count());

        verifier.set_keys(&keys).unwrap();
        prover.set_macs(&masks, &macs).unwrap();

        // Commit
        assert!(verifier.wants_flush());
        assert!(prover.wants_flush());

        let flush_v = verifier.send_flush().unwrap();
        let flush_p = prover.send_flush().unwrap();

        verifier.receive_flush(flush_p).unwrap();
        prover.receive_flush(flush_v).unwrap();

        // Prove
        assert!(verifier.wants_flush());
        assert!(prover.wants_flush());

        let flush_v = verifier.send_flush().unwrap();
        let flush_p = prover.send_flush().unwrap();

        verifier.receive_flush(flush_p).unwrap();
        prover.receive_flush(flush_v).unwrap();

        let b_v = b_v.try_recv().unwrap().unwrap();

        assert_eq!(b_v, [69u8; 16]);
    }
}
