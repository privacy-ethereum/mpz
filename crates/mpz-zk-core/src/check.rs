//! Quicksilver consistency check.

use std::mem;

use blake3::Hasher;
use cfg_if::cfg_if;
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use serde::{Deserialize, Serialize};

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
    transcript: Hasher,
    triples: Vec<Triple>,
    adjust: BitVec<u8>,
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

    pub(crate) fn write(&mut self, idx: usize, triples: &[Triple], adjust: &BitSlice<u8>) {
        self.triples[idx..idx + triples.len()].copy_from_slice(triples);
        self.adjust[idx..idx + triples.len()].copy_from_bitslice(adjust);
    }

    /// Returns `true` if there are gates to check.
    #[inline]
    pub(crate) fn wants_check(&self) -> bool {
        !self.triples.is_empty()
    }

    fn compute_chis(&self) -> Vec<Block> {
        // TODO: Consider using a PRG instead so computing the coefficients
        // can be done in parallel.
        let mut chi = Block::try_from(&self.transcript.finalize().as_bytes()[..16])
            .expect("block should be 16 bytes");
        let mut chis = Vec::with_capacity(self.triples.len());
        chis.push(chi);
        for _ in 1..self.triples.len() {
            chi = chi.gfmul(chi);
            chis.push(chi);
        }

        chis
    }

    /// Executes the prover check, returning `U` and `V` defined in Step 7.b.
    pub(crate) fn check_prover(
        &mut self,
        svole_choices: &[bool],
        svole_ev: &[Block],
    ) -> Result<UV> {
        #[inline]
        fn compute_terms(triple: Triple, chi: Block) -> (Block, Block) {
            let Triple { x, y, z } = triple;

            let u = x.gfmul(y).gfmul(chi);

            let a_10 = if x.lsb() { y } else { Block::ZERO };
            let a_11 = if y.lsb() { x } else { Block::ZERO };
            let v = (a_10 ^ a_11 ^ z).gfmul(chi);

            (u, v)
        }

        self.transcript.update(self.adjust.as_raw_slice());

        let chis = self.compute_chis();
        let macs = mem::take(&mut self.triples);
        cfg_if! {
            if #[cfg(all(feature = "rayon", not(feature = "force-st")))] {
                use rayon::prelude::*;

                let (mut u, mut v) = macs
                    .into_par_iter()
                    .zip(chis)
                    .map(|(macs, chi)| compute_terms(macs, chi))
                    .reduce(
                        || (Block::ZERO, Block::ZERO),
                        |(u_acc, v_acc), (u, v)| (u_acc ^ u, v_acc ^ v),
                    );
            } else {
                let (mut u, mut v) = macs
                    .into_iter()
                    .zip(chis)
                    .map(|(macs, chi)| compute_terms(macs, chi))
                    .fold(
                        (Block::ZERO, Block::ZERO),
                        |(u_acc, v_acc), (u, v)| (u_acc ^ u, v_acc ^ v),
                    );
            }
        }

        let (a_0, a_1) = vole_receiver(
            svole_choices.try_into().map_err(|_| CheckError::SVole)?,
            svole_ev.try_into().map_err(|_| CheckError::SVole)?,
        );

        u ^= a_0;
        v ^= a_1;

        self.transcript.update(&u.to_bytes());
        self.transcript.update(&v.to_bytes());

        self.adjust.clear();

        Ok(UV { u, v })
    }

    /// Executes the verifier check, returning `W` defined in Step 7.c.
    pub(crate) fn check_verifier(
        &mut self,
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

        self.transcript.update(self.adjust.as_raw_slice());

        let chis = self.compute_chis();
        let keys = mem::take(&mut self.triples);
        cfg_if! {
            if #[cfg(all(feature = "rayon", not(feature = "force-st")))] {
                use rayon::prelude::*;

                let mut w = keys
                    .into_par_iter()
                    .zip(chis)
                    .map(|(keys, chi)| compute_term(keys, chi, delta))
                    .reduce(
                        || Block::ZERO,
                        |w_acc, w| w_acc ^ w,
                    );
            } else {
                let mut w = keys
                    .into_iter()
                    .zip(chis)
                    .map(|(keys, chi)| compute_term(keys, chi, delta))
                    .fold(
                        Block::ZERO,
                        |w_acc, w| w_acc ^ w,
                    );
            }
        }

        let b = vole_sender(svole_keys.try_into().map_err(|_| CheckError::SVole)?);

        w ^= b;

        let UV { u, v } = uv;
        self.transcript.update(&u.to_bytes());
        self.transcript.update(&v.to_bytes());

        self.adjust.clear();

        if w != u ^ delta.gfmul(v) {
            // Invalid! Call the police.
            return Err(CheckError::Invalid);
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CheckError {
    #[error("incorrect number of sVOLE instances provided")]
    SVole,
    #[error("invalid consistency check")]
    Invalid,
}
