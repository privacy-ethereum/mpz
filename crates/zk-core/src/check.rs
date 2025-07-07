//! QuickSilver consistency check.

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
/// These are random linear combinations aggregated over one or more
/// circuit executions. The values `u` and `v` are kept private and will later
/// be masked (blinded) with random elements to derive the public values
/// `U = u + u*` and `V = v + v*` sent to the verifier.
#[derive(Debug, Default)]
pub(crate) struct ProverCheck {
    u: Option<Block>,
    v: Option<Block>,
}

impl ProverCheck {
    /// Aggregates the values for the consistency check.
    pub fn update(&mut self, u: Block, v: Block) {
        match &mut self.u {
            Some(prev_u) => *prev_u ^= u,
            None => self.u = Some(u),
        }

        match &mut self.v {
            Some(prev_v) => *prev_v ^= v,
            None => self.v = Some(v),
        }
    }

    /// Executes the prover check, returning `U` and `V` defined in Figure 5,
    /// Step 7.b.
    pub fn check(&mut self, svole_choices: &[bool], svole_ev: &[Block]) -> Result<UV> {
        let (a_0, a_1) = vole_receiver(
            svole_choices.try_into().map_err(|_| CheckError::SVole)?,
            svole_ev.try_into().map_err(|_| CheckError::SVole)?,
        );

        let u = self.u.ok_or(CheckError::NoExecutions)?;
        let v = self.v.ok_or(CheckError::NoExecutions)?;

        // Reset the values.
        self.u = None;
        self.v = None;

        Ok(UV {
            u: u ^ a_0,
            v: v ^ a_1,
        })
    }

    /// Returns `true` if there are gates to check.
    #[inline]
    pub(crate) fn wants_check(&self) -> bool {
        // `true` if at least one AND gate was executed.
        self.u.is_some()
    }
}

/// Verifier’s unmasked preprocessed values for the consistency check.
///
/// This is a random linear combination aggregated over one or more
/// circuit executions. The value will later be masked with a random
/// element to derive `W`.
#[derive(Debug, Default)]
pub(crate) struct VerifierCheck {
    w: Option<Block>,
}

impl VerifierCheck {
    /// Aggregates the values for the consistency check.
    pub fn update(&mut self, w: Block) {
        match &mut self.w {
            Some(prev_w) => *prev_w ^= w,
            None => self.w = Some(w),
        }
    }

    /// Executes the verifier check, returning `W` defined in Figure 5, Step
    /// 7.c.
    pub fn check(&mut self, delta: &Block, svole_keys: &[Block], uv: UV) -> Result<()> {
        let w = self.w.ok_or(CheckError::NoExecutions)?;

        let b = vole_sender(
            &svole_keys
                .try_into()
                .map_err(|_| CheckError::SVole)
                .unwrap(),
        );

        let UV { u, v } = uv;

        if w ^ b != u ^ delta.gfmul(v) {
            return Err(CheckError::Invalid);
        }

        // Reset the value.
        self.w = None;

        Ok(())
    }

    /// Returns `true` if there are gates to check.
    #[inline]
    pub(crate) fn wants_check(&self) -> bool {
        // `true` if at least one AND gate was executed.
        self.w.is_some()
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
