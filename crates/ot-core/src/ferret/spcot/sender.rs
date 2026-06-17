use blake3::{Hash, Hasher, hash};
use cfg_if::cfg_if;
use itybity::FromBitIterator;
use rand::Rng;
#[cfg(feature = "rayon")]
use rayon::prelude::*;

use mpz_core::{Block, bitvec::BitVec, utils::slices_from_lengths_mut};

use crate::ferret::cggm;
use mpz_fields::{Field, gf2_128::Gf2_128};
use zerocopy::IntoBytes;

use crate::ferret::{
    config::CSP,
    spcot::{MONOMIAL, fold_chis},
};

type Error = SPCOTSenderError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub(crate) struct SPCOTSender {
    /// Total length of the SPCOT vectors pending the consistency check.
    pending: usize,
    delta: Gf2_128,
    transcript: Hasher,
}

impl SPCOTSender {
    /// Creates a new SPCOT sender.
    pub(crate) fn new(delta: Gf2_128) -> Self {
        Self {
            pending: 0,
            delta,
            transcript: Hasher::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn delta(&self) -> Block {
        Block::from(self.delta)
    }

    #[cfg(test)]
    pub(crate) fn wants_check(&self) -> bool {
        self.pending != 0
    }

    /// Derandomizes the COT keys into the per-tree cGGM corrections.
    ///
    /// Split from [`SPCOTSender::expand`] so the caller can reuse the keys'
    /// buffer space for the output `vs` in between — this only reads `keys`.
    ///
    /// # Arguments
    ///
    /// * `log2_lengths` - log2 length of the SPCOT vectors.
    /// * `keys` - COT keys.
    /// * `masks` - Derandomized COT choices bits from the receiver.
    pub(crate) fn derandomize(
        &self,
        log2_lengths: &[usize],
        keys: &[Gf2_128],
        masks: &BitVec,
    ) -> Result<Vec<Gf2_128>> {
        let len_sum: usize = log2_lengths.iter().sum();
        if keys.len() != len_sum {
            return Err(ErrorRepr::KeyCount {
                expected: len_sum,
                actual: keys.len(),
            }
            .into());
        } else if masks.len() != len_sum {
            return Err(ErrorRepr::MaskCount {
                expected: len_sum,
                actual: masks.len(),
            }
            .into());
        }

        // After expansion these become the per-level corrections
        // c_i = K[r_i] ⊕ b_i * Δ ⊕ K_i^0, where K_i^0 is the left-node sum at
        // level i of the cGGM tree (Fig. 4 Step 3 of the Half-Tree paper,
        // https://eprint.iacr.org/2022/1431).
        let delta = self.delta;
        Ok(keys
            .iter()
            .zip(masks.iter().by_vals())
            .map(|(&key, b)| if b { key + delta } else { key })
            .collect())
    }

    /// Expands the cGGM trees into `vs`, consuming the corrections from
    /// [`SPCOTSender::derandomize`].
    ///
    /// Returns the cGGM tree corrections. `vs` must be presented to the
    /// consistency check unmodified.
    ///
    /// # Arguments
    ///
    /// * `log2_lengths` - log2 length of the SPCOT vectors.
    /// * `cs` - Derandomized corrections from [`SPCOTSender::derandomize`].
    /// * `masks` - Derandomized COT choices bits from the receiver.
    /// * `vs` - Output buffer for the SPCOT vectors. The vectors are stored as
    ///   field elements; the cGGM expansion reinterprets them as raw blocks
    ///   (`Gf2_128` is little-endian, matching `Block`'s byte order on all
    ///   supported, little-endian, targets).
    pub(crate) fn expand<R: Rng>(
        &mut self,
        rng: &mut R,
        log2_lengths: &[usize],
        mut cs: Vec<Gf2_128>,
        masks: &BitVec,
        vs: &mut [Gf2_128],
    ) -> Result<Vec<Gf2_128>> {
        let len_sum: usize = log2_lengths.iter().sum();
        if cs.len() != len_sum {
            return Err(ErrorRepr::KeyCount {
                expected: len_sum,
                actual: cs.len(),
            }
            .into());
        }

        let len: usize = log2_lengths.iter().map(|length| 1 << length).sum();
        if vs.len() != len {
            return Err(ErrorRepr::OutputLength {
                expected: len,
                actual: vs.len(),
            }
            .into());
        }

        let delta = self.delta;
        let spcot_lengths: Vec<_> = log2_lengths.iter().map(|length| 1 << length).collect();
        let seeds: Vec<Gf2_128> = (0..log2_lengths.len()).map(|_| rng.random()).collect();
        let vs = slices_from_lengths_mut(vs, &spcot_lengths);
        let cs_trees = slices_from_lengths_mut(&mut cs, log2_lengths);

        let iter = {
            cfg_if! {
                if #[cfg(feature = "rayon")] {
                    vs.into_par_iter()
                } else {
                    vs.into_iter()
                }
            }
        };

        iter.zip(cs_trees).zip(seeds).for_each(|((v, cs), seed)| {
            // Generate the SPCOT vector from the cGGM leaves. The leaves of
            // every tree sum to delta, which carries the punctured-point
            // correlation for free.
            //
            // The sums buffer lives on the stack: a tree deeper than 64
            // levels is impossible, as its leaves could not be allocated.
            let mut sums = [Gf2_128::ZERO; 64];
            let sums = &mut sums[..cs.len()];
            cggm::expand(delta, seed, v, sums);

            for (c, sum) in cs.iter_mut().zip(&*sums) {
                *c = *c + *sum;
            }
        });

        let masks_len = masks.len();
        self.transcript
            .update(&masks.as_raw_slice().as_bytes()[..masks_len.div_ceil(8)]);
        self.transcript.update(cs.as_bytes());
        self.pending += len;

        Ok(cs)
    }

    /// Performs the SPCOT consistency check.
    ///
    /// # Arguments
    ///
    /// * `keys` - COT keys.
    /// * `masks` - Derandomized COT choice bits from the receiver.
    /// * `vs` - The accumulated SPCOT vectors.
    pub(crate) fn check(
        &mut self,
        keys: &[Gf2_128],
        masks: &BitVec,
        vs: &[Gf2_128],
    ) -> Result<Hash> {
        if keys.len() != CSP {
            return Err(ErrorRepr::KeyCount {
                expected: CSP,
                actual: keys.len(),
            }
            .into());
        } else if masks.len() != CSP {
            return Err(ErrorRepr::MaskCount {
                expected: CSP,
                actual: masks.len(),
            }
            .into());
        } else if vs.len() != self.pending {
            return Err(ErrorRepr::OutputLength {
                expected: self.pending,
                actual: vs.len(),
            }
            .into());
        }

        // Step 8 in Figure 6.

        // Computes Y = Σᵢ yᵢ ⋅ Xⁱ, where yᵢ = y*ᵢ + x'ᵢ ⋅ Δ. By linearity this
        // is Σᵢ y*ᵢ ⋅ Xⁱ + x' ⋅ Δ, where x' is the choice bits packed into a
        // field element.
        let x = Gf2_128::from_lsb0_iter(masks.iter().by_vals());
        let y = Gf2_128::inner_product(keys, MONOMIAL) + self.delta * x;

        // Computes V = Y + Σₐ χₐ ⋅ vₐ
        let seed = *self.transcript.finalize().as_bytes();
        let (fold, _) = fold_chis(Block::try_from(&seed[0..16]).unwrap(), vs, &[]);
        let v = y + fold;

        // Computes H'(V)
        let hashed_v = hash(&Block::from(v).to_bytes());

        self.pending = 0;
        self.transcript.reset();

        Ok(hashed_v)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct SPCOTSenderError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("SPCOT sender error: {0}")]
enum ErrorRepr {
    #[error("incorrect key count, expected: {expected}, actual: {actual}")]
    KeyCount { expected: usize, actual: usize },
    #[error("incorrect mask count, expected: {expected}, actual: {actual}")]
    MaskCount { expected: usize, actual: usize },
    #[error("incorrect output buffer length, expected: {expected}, actual: {actual}")]
    OutputLength { expected: usize, actual: usize },
}
