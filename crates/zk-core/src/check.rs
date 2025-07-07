//! QuickSilver consistency check.

use std::{collections::HashMap, mem};

use blake3::Hasher;
use mpz_core::Block;
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

/// Prover’s unblinded preprocessed values for the consistency check.
///
/// These are random linear combinations for each circuit execution. The
/// values `u` and `v` are kept private and will later be masked (blinded)
/// with random elements to derive the public values `U = u + u*` and
/// `V = v + v*` sent to the verifier.
#[derive(Debug, Default)]
pub(crate) struct ProverCheck {
    /// Maps an id to the preprocessed values `u` and `v` from a single
    /// circuit execution.
    uv: HashMap<usize, (Block, Block)>,
    /// Next id to assign to the preprocessed values.
    next_id: usize,
}

impl ProverCheck {
    pub fn next_id(&mut self) -> usize {
        let next_id = self.next_id;
        self.next_id += 1;
        next_id
    }

    /// Inserts preprocessed values for the consistency check.
    pub fn insert(&mut self, u: Block, v: Block, id: usize) {
        self.uv.insert(id, (u, v));
    }

    /// Executes the prover check, returning `U` and `V` (for each circuit)
    /// defined in Figure 5, Step 7.b.
    pub fn check(&mut self, svole_choices: &[bool], svole_ev: &[Block]) -> Result<Vec<UV>> {
        if self.total_circuits() * 128 != svole_choices.len() {
            return Err(CheckError::SVole);
        }
        if svole_ev.len() != svole_choices.len() {
            return Err(CheckError::SVole);
        }

        let uv = mem::take(&mut self.uv);
        let mut uv: Vec<(usize, (Block, Block))> = uv.into_iter().collect();
        uv.sort_by_key(|&(k, _)| k);

        let uvs = uv
            .iter()
            .zip(svole_choices.chunks(128))
            .zip(svole_ev.chunks(128))
            .map(|(((_, (u, v)), svole_choices), svole_ev)| {
                let (a_0, a_1) = vole_receiver(
                    svole_choices.try_into().map_err(|_| CheckError::SVole)?,
                    svole_ev.try_into().map_err(|_| CheckError::SVole)?,
                );

                Ok(UV {
                    u: u ^ a_0,
                    v: v ^ a_1,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(uvs)
    }

    /// Returns `true` if there are gates to check.
    #[inline]
    pub(crate) fn wants_check(&self) -> bool {
        !self.uv.is_empty()
    }

    /// Returns the number of circuits that need to be checked.
    pub fn total_circuits(&self) -> usize {
        self.uv.len()
    }
}

/// Verifier’s unmasked preprocessed values for the consistency check.
///
/// This is a random linear combination for each circuit execution. The value
/// will later be masked with a random element to derive `W`.
#[derive(Debug, Default)]
pub(crate) struct VerifierCheck {
    /// Maps an id to the preprocessed values `w` from a single
    /// circuit execution.
    w: HashMap<usize, Block>,
    /// Next id to assign to the preprocessed values.
    next_id: usize,
}

impl VerifierCheck {
    pub fn next_id(&mut self) -> usize {
        let next_id = self.next_id;
        self.next_id += 1;
        next_id
    }

    /// Inserts a preprocessed value for the consistency check.
    pub fn insert(&mut self, w: Block, id: usize) {
        self.w.insert(id, w);
    }

    /// Executes the verifier check, returning `W` defined in Figure 5, Step
    /// 7.c.
    pub fn check(&mut self, delta: &Block, svole_keys: &[Block], uvs: Vec<UV>) -> Result<()> {
        if self.total_circuits() * 128 != svole_keys.len() {
            return Err(CheckError::SVole);
        }
        if self.total_circuits() != uvs.len() {
            return Err(CheckError::SVole);
        }

        let w = mem::take(&mut self.w);
        let mut w: Vec<(usize, Block)> = w.into_iter().collect();
        w.sort_by_key(|&(k, _)| k);

        w.iter()
            .zip(uvs)
            .zip(svole_keys.chunks(128))
            .map(|(((_, w), uv), svole_keys)| {
                let b = vole_sender(&svole_keys.try_into().map_err(|_| CheckError::SVole)?);

                let UV { u, v } = uv;

                if w ^ b != u ^ delta.gfmul(v) {
                    return Err(CheckError::Invalid);
                }

                Ok(())
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(())
    }

    /// Returns `true` if there are gates to check.
    #[inline]
    pub(crate) fn wants_check(&self) -> bool {
        !self.w.is_empty()
    }

    /// Returns the number of circuits that need to be checked.
    #[inline]
    pub fn total_circuits(&self) -> usize {
        self.w.len()
    }
}

/// Computes the values `u` and `v` as defined in [ProverCheck].
pub(crate) fn compute_uv(transcript: &mut Hasher, triples: &[Triple]) -> (Block, Block) {
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

    let chi =
        Block::try_from(&transcript.finalize().as_bytes()[..16]).expect("block should be 16 bytes");
    let chis = compute_chis(chi, triples.len());

    triples
        .iter()
        .zip(chis)
        .map(|(mac, chi)| compute_terms(*mac, chi))
        .fold((Block::ZERO, Block::ZERO), |(u_acc, v_acc), (u, v)| {
            (u_acc ^ u, v_acc ^ v)
        })
}

/// Computes the value `w` as defined in [VerifierCheck].
pub(crate) fn compute_w(transcript: &mut Hasher, triples: &[Triple], delta: &Block) -> Block {
    #[inline]
    fn compute_term(triple: Triple, chi: Block, delta: &Block) -> Block {
        let Triple { x, y, z } = triple;
        let b = x.gfmul(y) ^ delta.gfmul(z);
        b.gfmul(chi)
    }

    let chi =
        Block::try_from(&transcript.finalize().as_bytes()[..16]).expect("block should be 16 bytes");
    let chis = compute_chis(chi, triples.len());

    triples
        .iter()
        .zip(chis)
        .map(|(key, chi)| compute_term(*key, chi, delta))
        .fold(Block::ZERO, |w_acc, w| w_acc ^ w)
}

fn compute_chis(mut chi: Block, count: usize) -> Vec<Block> {
    debug_assert!(count > 0);

    let mut chis = Vec::with_capacity(count);
    chis.push(chi);
    for _ in 1..count {
        chi = chi.gfmul(chi);
        chis.push(chi);
    }

    chis
}

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("incorrect number of sVOLE instances provided")]
    SVole,
    #[error("invalid consistency check")]
    Invalid,
    #[error("check was called when no AND gates were executed")]
    NoExecutions,
}
