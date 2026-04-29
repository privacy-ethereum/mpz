//! VOLE-ZK verifier backend.

use std::{borrow::Cow, collections::VecDeque, marker::PhantomData};

use mpz_fields::Field;
use poly_proof_core::SubfieldOf;
use serde::Serialize;

use super::{
    PRODUCT_POLY_ID, Preparation, Proof, build_circuit, chunk_ranges_and_leftover,
    fan_in_tree_internal_nodes,
};
use crate::backend::{Backend, VerifierBackend};
use mpz_vole_core::{RVOLESender, RVOPESender, VoleAdjustment};

/// VOLE-ZK verifier backend.
pub struct VoleZkVerifierBackend<W, E, VL, VP>
where
    W: SubfieldOf<E>,
    E: Field,
    VL: RVOLESender<E>,
    VP: RVOPESender<E>,
{
    /// Fan-in of the product tree: each tree level
    /// merges `fan_in_degree` factors into one product wire.
    ///
    /// Must match the prover's setting or the proof will fail.
    fan_in_degree: usize,

    /// Verifier's global key.
    delta: E,

    /// RVOLE sender.
    rvole: VL,

    /// RVOPE sender for the mask(s) consumed at finalization.
    rvope: VP,

    /// QuickSilver polynomial-proof verifier.
    qs: poly_proof_core::verifier::Verifier<E>,

    /// Running size of the permutation vector this backend will verify
    /// over.
    total_count: usize,

    /// Total RVOLE correlations the backend will consume across its
    /// lifecycle.
    rvoles_alloced: usize,

    /// VoleAdjustments loaded from the prover's [`Preparation`].
    adjustments: VecDeque<VoleAdjustment<E>>,

    _phantom: PhantomData<W>,
}

impl<W, E, VL, VP> VoleZkVerifierBackend<W, E, VL, VP>
where
    W: SubfieldOf<E>,
    E: Field,
    VL: RVOLESender<E>,
    VP: RVOPESender<E>,
{
    /// Build a new verifier backend.
    ///
    /// # Arguments
    ///
    /// * `fan_in_degree` - Fan-in of the product tree (must be ≥ 1).
    /// * `delta` - Verifier's global key.
    /// * `rvole` - Random VOLE sender for committing intermediate
    ///   product wires.
    /// * `rvope` - Random VOPE sender for the mask consumed at QS
    ///   finalize time.
    pub fn new(
        fan_in_degree: usize,
        delta: E,
        rvole: VL,
        mut rvope: VP,
    ) -> Result<Self, VoleZkVerifierError> {
        if fan_in_degree < 2 {
            return Err(VoleZkVerifierError::InvalidFanIn(fan_in_degree));
        }
        let circuit = build_circuit(fan_in_degree);
        let qs = poly_proof_core::verifier::Verifier::new(delta, vec![circuit]);

        rvope
            .alloc(1, qs.required_vopes())
            .map_err(|e| VoleZkVerifierError::RvopeAlloc(Box::new(e)))?;

        Ok(Self {
            fan_in_degree,
            delta,
            rvole,
            rvope,
            qs,
            total_count: 0,
            rvoles_alloced: 0,
            adjustments: VecDeque::new(),
            _phantom: PhantomData,
        })
    }

    /// Configured fan-in degree.
    pub fn fan_in_degree(&self) -> usize {
        self.fan_in_degree
    }

    /// Verifier's `Δ`.
    pub fn delta_value(&self) -> E {
        self.delta
    }

    /// Running total of RVOLE correlations.
    #[cfg(test)]
    pub(super) fn rvoles_alloced(&self) -> usize {
        self.rvoles_alloced
    }
}

impl<W, E, VL, VP> Backend<W, E> for VoleZkVerifierBackend<W, E, VL, VP>
where
    W: SubfieldOf<E>,
    E: Field,
    VL: RVOLESender<E>,
    VP: RVOPESender<E>,
{
    type Error = VoleZkVerifierError;
    type Preparation = Preparation<E>;
    type BackendProof = Proof<E>;
}

impl<W, E, VL, VP> VerifierBackend<W, E> for VoleZkVerifierBackend<W, E, VL, VP>
where
    W: SubfieldOf<E>,
    E: Field + Serialize,
    VL: RVOLESender<E>,
    VP: RVOPESender<E>,
{
    fn delta(&self) -> E {
        self.delta
    }

    fn load_preparation(&mut self, preparation: Self::Preparation) {
        self.adjustments = preparation.adjustments.into();
    }

    fn verify(mut self, proof: Self::BackendProof) -> Result<(), Self::Error> {
        let Proof { qs_proof } = proof;

        // Step 1: consume the single pre-alloc'd RVOPE correlation.
        let rvope_out = self
            .rvope
            .try_send_vope(1)
            .map_err(|e| VoleZkVerifierError::RvopeConsume(Box::new(e)))?;
        let sum = rvope_out
            .evaluations
            .into_iter()
            .next()
            .expect("RVOPE try_send_vope(1) should return exactly one evaluation");
        let vope = poly_proof_core::VerifierVope { sum };

        // Step 2: run QS finalize.
        self.qs
            .finalize(&qs_proof, &vope)
            .map_err(|e| VoleZkVerifierError::QsVerify(Box::new(e)))
    }

    fn alloc(&mut self, n: usize) -> Result<(), Self::Error> {
        self.total_count = self.total_count.saturating_add(n);
        // 2× because the product is computed for each of the two
        // permutation vectors.
        let target = 2 * fan_in_tree_internal_nodes(self.total_count, self.fan_in_degree);
        let delta = target - self.rvoles_alloced;
        if delta > 0 {
            self.rvole
                .alloc(delta)
                .map_err(|e| VoleZkVerifierError::RvoleAlloc(Box::new(e)))?;
            self.rvoles_alloced = target;
        }
        Ok(())
    }

    fn product(
        &mut self,
        transcript: &mut blake3::Hasher,
        factor_keys: &[E],
    ) -> Result<E, Self::Error> {
        let n = factor_keys.len();
        if n == 0 {
            return Err(VoleZkVerifierError::EmptyInput);
        }
        if n == 1 {
            return Ok(factor_keys[0]);
        }

        // Working set for the current tree level. Borrowed from the
        // input on iter 0, replaced with an owned Vec at the end of
        // every iter — so no upfront copy of the leaves.
        let mut current_keys: Cow<'_, [E]> = Cow::Borrowed(factor_keys);
        let eps = self.fan_in_degree;

        while current_keys.len() > 1 {
            let level_size = current_keys.len();
            let (mut chunk_ranges, mut passthroughs) = chunk_ranges_and_leftover(level_size, eps);
            // Terminal level (`level_size < eps`): no next iteration to
            // defer leftover to, so commit it here as a single short
            // chunk.
            if chunk_ranges.is_empty() {
                chunk_ranges = vec![(0, level_size)];
                passthroughs = Vec::new();
            }
            let n_chunks = chunk_ranges.len();

            // Consume the prover's adjustment for this level.
            let adjustment = self
                .adjustments
                .pop_front()
                .ok_or(VoleZkVerifierError::AdjustmentUnderflow)?;
            if adjustment.diffs.len() != n_chunks {
                return Err(VoleZkVerifierError::AdjustmentShapeMismatch {
                    expected: n_chunks,
                    actual: adjustment.diffs.len(),
                });
            }

            // Absorb into the transcript.
            transcript.update(b"permutation-proof::vole-adjustment");
            transcript.update(&bcs::to_bytes(&adjustment).expect("serialize"));

            // Consume and derandomize random VOLEs.
            let rvole_out = self
                .rvole
                .try_send_vole(n_chunks)
                .map_err(|e| VoleZkVerifierError::RvoleConsume(Box::new(e)))?;

            // Pre-sized to fit the trailing passthroughs we'll append at
            // end-of-iter, so the next-level assembly is realloc-free.
            let mut prod_keys: Vec<E> = Vec::with_capacity(n_chunks + passthroughs.len());
            prod_keys.extend(
                rvole_out
                    .keys
                    .iter()
                    .zip(&adjustment.diffs)
                    .map(|(k, d)| *k - self.delta * *d),
            );

            // Build the QS accumulate inputs for this level, one
            // evaluation per chunk with ε+1 keys.
            let neg_delta = -self.delta;
            let mut chunk_keys_store: Vec<Vec<E>> = Vec::with_capacity(n_chunks);
            for (i, &(start, end)) in chunk_ranges.iter().enumerate() {
                let real_count = end - start;
                let mut keys = Vec::with_capacity(eps + 1);
                keys.extend_from_slice(&current_keys[start..end]);
                for _ in real_count..eps {
                    // Padding convention: the prover uses (value=1, mac=0).
                    // Under the invariant `mac = key + Δ·value`, that forces
                    // the matching key to `mac − Δ·value = −Δ·1 = −Δ`.
                    // Only ever fires for the last chunk — full
                    // chunks have `real_count == ε` and the loop is empty.
                    keys.push(neg_delta);
                }
                keys.push(prod_keys[i]);
                chunk_keys_store.push(keys);
            }

            // Draw a fresh challenge for this tree-walk level.
            let chi = crate::draw_field::<E>(transcript, b"permutation-proof::qs-chi");
            let evaluations: Vec<(usize, &[E])> = chunk_keys_store
                .iter()
                .map(|k| (PRODUCT_POLY_ID, k.as_slice()))
                .collect();
            self.qs
                .accumulate(&evaluations, chi)
                .map_err(|e| VoleZkVerifierError::QsAccumulate(Box::new(e)))?;

            // Assemble the next level.
            prod_keys.extend(passthroughs.iter().map(|&idx| current_keys[idx]));

            current_keys = Cow::Owned(prod_keys);
        }

        Ok(current_keys[0])
    }
}

/// Errors produced by [`VoleZkVerifierBackend`].
#[derive(Debug, thiserror::Error)]
pub enum VoleZkVerifierError {
    /// The underlying RVOLE provider's `alloc` rejected the request.
    #[error("RVOLE alloc failed: {0}")]
    RvoleAlloc(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The underlying RVOPE provider's `alloc` rejected the request.
    #[error("RVOPE alloc failed: {0}")]
    RvopeAlloc(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The QuickSilver verifier rejected an `accumulate` call.
    #[error("QuickSilver accumulate failed: {0}")]
    QsAccumulate(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The RVOPE provider failed to deliver the pre-allocated correlation.
    #[error("RVOPE consume failed: {0}")]
    RvopeConsume(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The underlying RVOLE provider failed to produce preprocessed
    /// correlations.
    #[error("RVOLE consume failed: {0}")]
    RvoleConsume(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The QuickSilver polynomial-proof verifier rejected the `finalize`
    /// call.
    #[error("QuickSilver verify failed: {0}")]
    QsVerify(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The verifier's tree walk needed another VoleAdjustment but the
    /// loaded proof had none left.
    #[error("ran out of VoleAdjustments while walking the fan-in tree")]
    AdjustmentUnderflow,

    /// A consumed VoleAdjustment's `diffs` length disagreed with the
    /// number of chunks the verifier expected at this tree level.
    #[error(
        "VoleAdjustment shape mismatch: expected {expected} diffs for this level, got {actual}"
    )]
    AdjustmentShapeMismatch {
        /// Number of chunks the verifier expected at this level.
        expected: usize,
        /// Number of diffs actually present in the adjustment.
        actual: usize,
    },

    /// `fan_in_degree` was less than the minimum supported value (2).
    #[error("fan_in_degree must be at least 2; got {0}")]
    InvalidFanIn(usize),

    /// `product` was called with an empty factor-keys slice.
    #[error("product called with empty factor-keys slice")]
    EmptyInput,
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_fields::gf2_128::Gf2_128;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::backend::VerifierBackend;
    use mpz_vole_core::ideal::{
        rvole::{IdealRVOLESender, ideal_rvole},
        rvope::IdealRVOPESender,
    };

    /// Build a verifier-only backend with no pre-filled correlations.
    /// For tests that exercise bookkeeping.
    fn build_verifier_only(
        rng_seed: u64,
        eps: usize,
    ) -> VoleZkVerifierBackend<Gf2_128, Gf2_128, IdealRVOLESender<Gf2_128>, IdealRVOPESender<Gf2_128>>
    {
        let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
        let delta: Gf2_128 = rng.random();
        let rvole_seed: u64 = rng.random();
        let rvope_seed: u64 = rng.random();
        let (rvole_s, _rvole_r) = ideal_rvole::<Gf2_128, Gf2_128>(rvole_seed, delta);
        let rvope_s = IdealRVOPESender::<Gf2_128>::new(rvope_seed, delta);
        VoleZkVerifierBackend::<Gf2_128, Gf2_128, _, _>::new(eps, delta, rvole_s, rvope_s).unwrap()
    }

    /// Test cumulative-alloc contract.
    #[test]
    fn alloc_forwards_cumulative_deltas() {
        let mut verifier = build_verifier_only(0xE5, 8);
        assert_eq!(verifier.rvoles_alloced(), 0);

        // running n=5  → internal_nodes(5,8)=1,  target=2, delta=+2
        verifier.alloc(5).unwrap();
        assert_eq!(verifier.rvoles_alloced(), 2);

        // running n=12 → internal_nodes(12,8)=2, target=4, delta=+2
        verifier.alloc(7).unwrap();
        assert_eq!(verifier.rvoles_alloced(), 4);

        // running n=16 → internal_nodes(16,8)=3, target=6, delta=+2
        verifier.alloc(4).unwrap();
        assert_eq!(verifier.rvoles_alloced(), 6);
    }

    /// Empty-input short-circuit.
    #[test]
    fn product_rejects_empty_input() {
        let mut verifier = build_verifier_only(0xE6, 8);
        let mut transcript = blake3::Hasher::new();
        let err = verifier
            .product(&mut transcript, &[])
            .expect_err("empty input must surface an error");
        assert!(
            matches!(err, VoleZkVerifierError::EmptyInput),
            "expected EmptyInput, got {err:?}"
        );
    }

    /// Singleton short-circuit.
    #[test]
    fn product_passes_through_singleton() {
        let mut verifier = build_verifier_only(0xE7, 8);
        let mut rng = ChaCha8Rng::seed_from_u64(0xE7_1234);
        let k: Gf2_128 = rng.random();

        // Load an empty `Preparation` — the singleton path must not
        // pop any adjustments off the queue.
        verifier.load_preparation(Preparation {
            adjustments: vec![],
        });

        let mut transcript = blake3::Hasher::new();
        let ret_k = verifier
            .product(&mut transcript, &[k])
            .expect("singleton passthrough must succeed");
        assert_eq!(ret_k, k);
    }

    /// Test `VoleAdjustment` underflow.
    #[test]
    fn product_underflow_on_short_preparation() {
        let mut verifier = build_verifier_only(0xE8, 4);
        // `n = 4, eps = 4`: tree walks exactly one level (one chunk).
        // Loading an empty Preparation means the first `pop_front` at
        // level 0 returns `None` → AdjustmentUnderflow.
        verifier.load_preparation(Preparation {
            adjustments: vec![],
        });

        let mut rng = ChaCha8Rng::seed_from_u64(0xE8_1234);
        let keys: Vec<Gf2_128> = (0..4).map(|_| rng.random()).collect();

        let mut transcript = blake3::Hasher::new();
        let err = verifier
            .product(&mut transcript, &keys)
            .expect_err("short Preparation must surface an error");
        assert!(
            matches!(err, VoleZkVerifierError::AdjustmentUnderflow),
            "expected AdjustmentUnderflow, got {err:?}"
        );
    }

    /// Per-level shape check.
    #[test]
    fn product_shape_mismatch_on_wrong_diffs_length() {
        let mut verifier = build_verifier_only(0xE9, 4);
        // `n = 4, eps = 4`: level 0 has exactly one chunk, so the
        // matching adjustment must carry `diffs.len() == 1`. Load one
        // with 2 diffs to trip the shape check.
        verifier.load_preparation(Preparation {
            adjustments: vec![mpz_vole_core::VoleAdjustment {
                diffs: vec![Gf2_128::one(), Gf2_128::one()],
            }],
        });

        let mut rng = ChaCha8Rng::seed_from_u64(0xE9_1234);
        let keys: Vec<Gf2_128> = (0..4).map(|_| rng.random()).collect();

        let mut transcript = blake3::Hasher::new();
        let err = verifier
            .product(&mut transcript, &keys)
            .expect_err("wrong-shape adjustment must surface an error");
        match err {
            VoleZkVerifierError::AdjustmentShapeMismatch { expected, actual } => {
                assert_eq!(expected, 1, "expected 1 chunk at level 0");
                assert_eq!(actual, 2, "loaded adjustment had 2 diffs");
            }
            other => panic!("expected AdjustmentShapeMismatch, got {other:?}"),
        }
    }
}
