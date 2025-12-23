//! QuickSilver consistency check.

use std::mem;

use blake3::Hasher;
use cfg_if::cfg_if;
use mpz_core::{
    Block,
    bitvec::{BitSlice, BitVec},
};
use serde::{Deserialize, Serialize};
use zerocopy::IntoBytes;

use crate::vole::{vole_receiver, vole_sender};

type Result<T> = core::result::Result<T, CheckError>;

/// Values sent from the prover to the verifier for the consistency check.
#[derive(Debug, Serialize, Deserialize)]
pub struct UV {
    u: Block,
    v: Block,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Triple {
    pub(crate) x: Block,
    pub(crate) y: Block,
    pub(crate) z: Block,
}

#[derive(Debug, Default)]
pub(crate) struct Check {
    triples: Vec<Triple>,
    adjust: BitVec,
}

impl Check {
    /// Reserves capacity for at least `n` AND gates, returns the starting
    /// index.
    pub(crate) fn reserve(&mut self, n: usize) -> usize {
        let idx = self.triples.len();
        self.triples.resize_with(idx + n, Default::default);
        self.adjust.resize_with(idx + n, |_| Default::default());
        idx
    }

    pub(crate) fn write(&mut self, idx: usize, triples: &[Triple], adjust: &BitSlice) {
        self.triples[idx..idx + triples.len()].copy_from_slice(triples);
        self.adjust[idx..idx + triples.len()].copy_from_bitslice(adjust);
    }

    /// Returns `true` if there are gates to check.
    #[inline]
    pub(crate) fn wants_check(&self) -> bool {
        !self.triples.is_empty()
    }

    /// Computes independent starting points for parallel chi computation.
    /// Bootstrap 16 values via squaring, hash each to get independent starts.
    fn compute_chi_starts(chi: Block, segment_size: usize) -> [Block; 16] {
        use blake3::Hasher;

        // Bootstrap 16 values via squaring
        let mut bootstrapped = [Block::ZERO; 16];
        let mut current = chi;
        for b in &mut bootstrapped {
            *b = current;
            current = current.gfmul(current);
        }

        // Hash each to get independent starting points
        let mut starts = [Block::ZERO; 16];
        for (i, boot) in bootstrapped.iter().enumerate() {
            let mut hasher = Hasher::new();
            hasher.update(&boot.to_bytes());
            hasher.update(&(i as u64).to_le_bytes());
            hasher.update(&(segment_size as u64).to_le_bytes());
            let hash = hasher.finalize();
            starts[i] =
                Block::try_from(&hash.as_bytes()[..16]).expect("hash should be at least 16 bytes");
        }

        starts
    }

    /// Executes the prover check, returning `U` and `V` defined in Figure 5,
    /// Step 7.b.
    pub(crate) fn check_prover(
        &mut self,
        transcript: &mut Hasher,
        svole_choices: &[bool],
        svole_ev: &[Block],
    ) -> Result<UV> {
        #[inline]
        fn compute_terms(triple: Triple, chi: Block) -> (Block, Block) {
            let Triple { x, y, z } = triple;

            let u = x.gfmul(y).gfmul(chi);

            // (Note that the LSB of a MAC contains the authenticated bit).
            let a_10 = if x.lsb() { y } else { Block::ZERO };
            let a_11 = if y.lsb() { x } else { Block::ZERO };
            let v = (a_10 ^ a_11 ^ z).gfmul(chi);

            (u, v)
        }

        let adjust_len = self.adjust.len();
        transcript.update(&self.adjust.as_raw_slice().as_bytes()[..adjust_len.div_ceil(8)]);

        let chi = Block::try_from(&transcript.finalize().as_bytes()[..16])
            .expect("block should be 16 bytes");
        let macs = mem::take(&mut self.triples);

        // Computation with pre-split lanes.
        const PARALLELISM: usize = 16;
        let n = macs.len();
        let segment_size = n.div_ceil(PARALLELISM);
        let starts = Self::compute_chi_starts(chi, segment_size);

        let process_segment = |segment: &[Triple], chi_start: Block| {
            let mut current_chi = chi_start;
            let mut u_acc = Block::ZERO;
            let mut v_acc = Block::ZERO;

            for &triple in segment {
                let (u, v) = compute_terms(triple, current_chi);
                u_acc ^= u;
                v_acc ^= v;
                current_chi = current_chi.gfmul(current_chi);
            }

            (u_acc, v_acc)
        };

        cfg_if! {
            if #[cfg(feature = "rayon")] {
                use rayon::prelude::*;

                let (mut u, mut v) = macs
                    .par_chunks(segment_size)
                    .zip(starts.into_par_iter())
                    .map(|(segment, chi_start)| process_segment(segment, chi_start))
                    .reduce(
                        || (Block::ZERO, Block::ZERO),
                        |(u1, v1), (u2, v2)| (u1 ^ u2, v1 ^ v2),
                    );
            } else {
                let (mut u, mut v) = macs
                    .chunks(segment_size)
                    .zip(starts.into_iter())
                    .map(|(segment, chi_start)| process_segment(segment, chi_start))
                    .fold(
                        (Block::ZERO, Block::ZERO),
                        |(u1, v1), (u2, v2)| (u1 ^ u2, v1 ^ v2),
                    );
            }
        }

        let (a_0, a_1) = vole_receiver(
            svole_choices.try_into().map_err(|_| CheckError::SVole)?,
            svole_ev.try_into().map_err(|_| CheckError::SVole)?,
        );

        u ^= a_0;
        v ^= a_1;

        transcript.update(&u.to_bytes());
        transcript.update(&v.to_bytes());

        self.adjust.clear();

        Ok(UV { u, v })
    }

    /// Executes the verifier check, returning `W` defined in Figure 5, Step
    /// 7.c.
    pub(crate) fn check_verifier(
        &mut self,
        transcript: &mut Hasher,
        delta: &Block,
        svole_keys: &[Block],
        uv: UV,
    ) -> Result<()> {
        #[inline]
        fn compute_term(triple: Triple, chi: Block, delta: &Block) -> Block {
            let Triple { x, y, z } = triple;
            let b = x.gfmul(y) ^ delta.gfmul(z);
            b.gfmul(chi)
        }

        let adjust_len = self.adjust.len();
        transcript.update(&self.adjust.as_raw_slice().as_bytes()[..adjust_len.div_ceil(8)]);

        let chi = Block::try_from(&transcript.finalize().as_bytes()[..16])
            .expect("block should be 16 bytes");
        let keys = mem::take(&mut self.triples);

        // Computation with pre-split lanes.
        const PARALLELISM: usize = 16;
        let n = keys.len();
        let segment_size = n.div_ceil(PARALLELISM);
        let starts = Self::compute_chi_starts(chi, segment_size);

        let process_segment = |segment: &[Triple], chi_start: Block| {
            let mut current_chi = chi_start;
            let mut w_acc = Block::ZERO;

            for &triple in segment {
                let w = compute_term(triple, current_chi, delta);
                w_acc ^= w;
                current_chi = current_chi.gfmul(current_chi);
            }

            w_acc
        };

        cfg_if! {
            if #[cfg(feature = "rayon")] {
                use rayon::prelude::*;

                let mut w = keys
                    .par_chunks(segment_size)
                    .zip(starts.into_par_iter())
                    .map(|(segment, chi_start)| process_segment(segment, chi_start))
                    .reduce(
                        || Block::ZERO,
                        |w1, w2| w1 ^ w2,
                    );
            } else {
                let mut w = keys
                    .chunks(segment_size)
                    .zip(starts.into_iter())
                    .map(|(segment, chi_start)| process_segment(segment, chi_start))
                    .fold(
                        Block::ZERO,
                        |w1, w2| w1 ^ w2,
                    );
            }
        }

        let b = vole_sender(svole_keys.try_into().map_err(|_| CheckError::SVole)?);

        w ^= b;

        let UV { u, v } = uv;
        transcript.update(&u.to_bytes());
        transcript.update(&v.to_bytes());

        self.adjust.clear();

        if w != u ^ delta.gfmul(v) {
            // Invalid! Call the police.
            return Err(CheckError::Invalid);
        }

        Ok(())
    }

    /// Returns the total number of triples that need to be checked.
    pub(crate) fn total(&self) -> usize {
        self.triples.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CheckError {
    #[error("incorrect number of sVOLE instances provided")]
    SVole,
    #[error("invalid consistency check")]
    Invalid,
}
