//! VOLE-ZK prover backend.

use std::{borrow::Cow, marker::PhantomData};

use mpz_common::future::Output;
use mpz_fields::{ExtensionField, Field};
use mpz_poly_proof_core::ConstraintId;
use serde::{Deserialize, Serialize};

use super::{build_product_constraints, chunk_ranges_and_leftover, fan_in_tree_internal_nodes};
use crate::backend::{Backend, ProverBackend};
use mpz_vole_core::{
    DerandVOLEReceiver, RVOLEReceiver, RVOPEReceiver, VOLEReceiver, VoleAdjustment,
};

/// VOLE-ZK prover backend.
pub struct VoleZkProverBackend<W, E, VL, VP>
where
    W: Field,
    E: ExtensionField<W> + ExtensionField<E>,
    VL: RVOLEReceiver<E, E>,
    VP: RVOPEReceiver<E>,
{
    /// Fan-in of the product tree: each tree level
    /// merges `fan_in_degree` factors into one product wire.
    fan_in_degree: usize,

    /// Derandomized full-field VOLE receiver for committing the
    /// intermediate product wires.
    rvole: DerandVOLEReceiver<VL, E, E>,

    /// RVOPE receiver for the mask(s) consumed at finalization.
    rvope: VP,

    /// QuickSilver polynomial-proof prover.
    qs: mpz_poly_proof_core::prover::Prover<E>,

    /// Id of the single product constraint registered with `qs`.
    product_constraint: ConstraintId,

    /// Running size of the permutation vector this backend will prove
    /// over.
    total_count: usize,

    /// Total RVOLE correlations the backend will consume across its
    /// lifecycle.
    rvoles_alloced: usize,

    /// VoleAdjustments emitted by the tree walk, one per level, in
    /// the order the verifier expects.
    pending_adjustments: Vec<VoleAdjustment<E>>,

    /// QuickSilver `accumulate` arguments, one per tree level,
    /// replayed at finalize.
    pending_qs_accumulate: Vec<DeferredAccumulate<E>>,

    _phantom: PhantomData<W>,
}

impl<W, E, VL, VP> VoleZkProverBackend<W, E, VL, VP>
where
    W: Field,
    E: ExtensionField<W> + ExtensionField<E>,
    VL: RVOLEReceiver<E, E>,
    VP: RVOPEReceiver<E>,
{
    /// Build a new prover backend.
    ///
    /// # Arguments
    ///
    /// * `fan_in_degree` - Fan-in of the product tree (must be ≥ 1).
    /// * `rvole` - Random VOLE receiver for committing intermediate
    ///   product wires.
    /// * `rvope` - Random VOPE receiver for the mask consumed at QS
    ///   finalize time.
    pub fn new(fan_in_degree: usize, rvole: VL, mut rvope: VP) -> Result<Self, VoleZkProverError> {
        if fan_in_degree < 2 {
            return Err(VoleZkProverError::InvalidFanIn(fan_in_degree));
        }
        let (constraints, product_constraint) = build_product_constraints::<E>(fan_in_degree);
        let qs = mpz_poly_proof_core::prover::Prover::new(&constraints);

        rvope
            .alloc(1, qs.required_vopes())
            .map_err(|e| VoleZkProverError::RvopeAlloc(Box::new(e)))?;

        Ok(Self {
            fan_in_degree,
            rvole: DerandVOLEReceiver::new(rvole),
            rvope,
            qs,
            product_constraint,
            total_count: 0,
            rvoles_alloced: 0,
            pending_adjustments: Vec::new(),
            pending_qs_accumulate: Vec::new(),
            _phantom: PhantomData,
        })
    }

    /// Configured fan-in degree.
    pub fn fan_in_degree(&self) -> usize {
        self.fan_in_degree
    }

    /// Running total of RVOLE correlations.
    #[cfg(test)]
    pub(super) fn rvoles_alloced(&self) -> usize {
        self.rvoles_alloced
    }
}

/// Preparation message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preparation<E: Field> {
    /// Per-level VoleAdjustment DTOs, in emission order.
    pub adjustments: Vec<VoleAdjustment<E>>,
}

/// Proof message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<E: Field> {
    /// QuickSilver polynomial-proof message.
    pub qs_proof: mpz_poly_proof_core::ProofMessage<E>,
}

impl<W, E, VL, VP> Backend<W, E> for VoleZkProverBackend<W, E, VL, VP>
where
    W: Field,
    E: ExtensionField<W> + ExtensionField<E>,
    VL: RVOLEReceiver<E, E>,
    VP: RVOPEReceiver<E>,
{
    type Error = VoleZkProverError;
    type Preparation = Preparation<E>;
    type BackendProof = Proof<E>;
}

impl<W, E, VL, VP> ProverBackend<W, E> for VoleZkProverBackend<W, E, VL, VP>
where
    W: Field,
    E: ExtensionField<W>
        + ExtensionField<E>
        + Serialize
        + zerocopy::IntoBytes
        + zerocopy::FromBytes,
    VL: RVOLEReceiver<E, E>,
    VP: RVOPEReceiver<E>,
{
    fn drain_preparation(&mut self) -> Result<Self::Preparation, Self::Error> {
        Ok(Preparation {
            adjustments: std::mem::take(&mut self.pending_adjustments),
        })
    }

    fn prove(mut self) -> Result<Self::BackendProof, Self::Error> {
        // Step 1: replay the QS accumulate calls that `product`
        // buffered earlier.
        for DeferredAccumulate { seed, evaluations } in
            std::mem::take(&mut self.pending_qs_accumulate)
        {
            let refs: Vec<(ConstraintId, &[E], &[E])> = evaluations
                .iter()
                .map(|(id, m, v)| (*id, m.as_slice(), v.as_slice()))
                .collect();
            // W = E here: tree-walk wires are already extension-field
            // elements (post-`prepare` collapse), so the `accumulate`
            // generic uses the trivial `E: ExtensionField<E>` impl.
            self.qs
                .accumulate::<E>(&refs, seed)
                .map_err(|e| VoleZkProverError::QsAccumulate(Box::new(e)))?;
        }

        // Step 2: consume the single RVOPE correlation.
        let rvope_out = self
            .rvope
            .try_recv_vope(1)
            .map_err(|e| VoleZkProverError::RvopeConsume(Box::new(e)))?;
        // Move the coefficients out.
        let coeffs = rvope_out
            .polynomials
            .into_iter()
            .next()
            .expect("RVOPE try_recv_vope(1) should return exactly one polynomial");
        let vope = mpz_poly_proof_core::ProverVope { coeffs };

        // Step 3: run QS finalize.
        let qs_proof = self
            .qs
            .finalize(&vope)
            .map_err(|e| VoleZkProverError::QsFinalize(Box::new(e)))?;

        Ok(Proof { qs_proof })
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
                .map_err(|e| VoleZkProverError::RvoleAlloc(Box::new(e)))?;
            self.rvoles_alloced = target;
        }
        Ok(())
    }

    fn product(
        &mut self,
        transcript: &mut blake3::Hasher,
        factor_values: &[E],
        factor_macs: &[E],
    ) -> Result<(E, E), Self::Error> {
        if factor_values.len() != factor_macs.len() {
            return Err(VoleZkProverError::FactorLengthMismatch {
                values: factor_values.len(),
                macs: factor_macs.len(),
            });
        }

        let n = factor_values.len();
        if n == 0 {
            return Err(VoleZkProverError::EmptyInput);
        }
        if n == 1 {
            // Singleton: no chunk to commit, just pass the wire through.
            return Ok((factor_values[0], factor_macs[0]));
        }

        // Working set for the current tree level. Borrowed from the
        // input on iter 0, replaced with an owned Vec at the end of
        // every iter — so no upfront copy of the leaves.
        let mut current_values: Cow<'_, [E]> = Cow::Borrowed(factor_values);
        let mut current_macs: Cow<'_, [E]> = Cow::Borrowed(factor_macs);
        let eps = self.fan_in_degree;

        // Walk the tree bottom-up until a single root wire remains.
        while current_values.len() > 1 {
            let level_size = current_values.len();
            let (mut chunk_ranges, mut passthroughs) = chunk_ranges_and_leftover(level_size, eps);
            // Terminal level (`level_size < eps`): no next iteration to
            // defer leftover to, so commit it here as a single short
            // chunk.
            if chunk_ranges.is_empty() {
                chunk_ranges = vec![(0, level_size)];
                passthroughs = Vec::new();
            }

            // Compute each chunk's cleartext product. Pre-sized to fit
            // the trailing passthroughs we'll append at end-of-iter,
            // so the next-level assembly is realloc-free.
            let mut chunk_products: Vec<E> =
                Vec::with_capacity(chunk_ranges.len() + passthroughs.len());
            chunk_products.extend(chunk_ranges.iter().map(|&(start, end)| {
                current_values[start..end]
                    .iter()
                    .copied()
                    .fold(E::one(), |acc, x| acc * x)
            }));

            // Commit products.
            let mut batch_fut = self
                .rvole
                .queue_recv_vole(&chunk_products)
                .map_err(|e| VoleZkProverError::RvoleAlloc(Box::new(e)))?;

            let adjustment = self
                .rvole
                .adjust()
                .map_err(|e| VoleZkProverError::RvoleAlloc(Box::new(e)))?;

            let mut prod_macs: Vec<E> = batch_fut
                .try_recv()
                .expect("VOLE adjust() should not cancel queued futures")
                .expect("VOLE future should resolve after adjust() returns")
                .macs;

            transcript.update(b"permutation-proof::vole-adjustment");
            transcript.update(&bcs::to_bytes(&adjustment).expect("serialize"));

            // Buffer the DTO for transport.
            self.pending_adjustments.push(adjustment);

            // Build the QS accumulate inputs. For each chunk, assemble
            // one evaluation with `ε + 1` variables: ε factor slots
            // followed by the prod slot.
            let mut chunk_macs_store: Vec<Vec<E>> = Vec::with_capacity(chunk_ranges.len());
            let mut chunk_values_store: Vec<Vec<E>> = Vec::with_capacity(chunk_ranges.len());
            for (i, &(start, end)) in chunk_ranges.iter().enumerate() {
                let real_count = end - start;
                let mut macs = Vec::with_capacity(eps + 1);
                let mut values = Vec::with_capacity(eps + 1);
                macs.extend_from_slice(&current_macs[start..end]);
                values.extend_from_slice(&current_values[start..end]);
                // Pad short chunks up to ε with the public-coefficient
                // 1: value = 1 leaves the circuit's product unchanged
                // (1 is the multiplicative identity); MAC = 0 is the
                // IT-MAC encoding, pinned by `key = -Δ` on the verifier
                // side. Only ever fires for the last chunk — full
                // chunks have `real_count == ε` and the loop is empty.
                for _ in real_count..eps {
                    macs.push(<E as Field>::zero());
                    values.push(<E as Field>::one());
                }
                macs.push(prod_macs[i]);
                values.push(chunk_products[i]);
                chunk_macs_store.push(macs);
                chunk_values_store.push(values);
            }

            // Draw a fresh PRG seed for this tree-walk level.
            let seed = crate::draw_seed(transcript, b"permutation-proof::qs-seed");
            let evaluations: Vec<(ConstraintId, Vec<E>, Vec<E>)> = chunk_macs_store
                .into_iter()
                .zip(chunk_values_store)
                .map(|(m, v)| (self.product_constraint, m, v))
                .collect();
            self.pending_qs_accumulate
                .push(DeferredAccumulate { seed, evaluations });

            // Assemble the next level.
            chunk_products.extend(passthroughs.iter().map(|&idx| current_values[idx]));
            prod_macs.extend(passthroughs.iter().map(|&idx| current_macs[idx]));

            current_values = Cow::Owned(chunk_products);
            current_macs = Cow::Owned(prod_macs);
        }

        Ok((current_values[0], current_macs[0]))
    }
}

/// One tree-walk level's deferred QuickSilver accumulate call.
struct DeferredAccumulate<E: Field> {
    /// PRG seed drawn from the transcript.
    seed: [u8; 32],
    /// Per-chunk `(constraint_id, macs, values)` tuples.
    evaluations: Vec<(ConstraintId, Vec<E>, Vec<E>)>,
}

/// Errors produced by [`VoleZkProverBackend`].
#[derive(Debug, thiserror::Error)]
pub enum VoleZkProverError {
    /// The underlying RVOLE provider's `alloc` rejected the request.
    #[error("RVOLE alloc failed: {0}")]
    RvoleAlloc(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The underlying RVOPE provider's `alloc` rejected the request.
    #[error("RVOPE alloc failed: {0}")]
    RvopeAlloc(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The QuickSilver prover rejected an `accumulate` call.
    #[error("QuickSilver accumulate failed: {0}")]
    QsAccumulate(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The RVOPE provider failed to deliver the pre-allocated correlation
    /// when QS finalize tried to consume it.
    #[error("RVOPE consume failed: {0}")]
    RvopeConsume(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The QuickSilver prover rejected the `finalize` call.
    #[error("QuickSilver finalize failed: {0}")]
    QsFinalize(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// `fan_in_degree` was less than the minimum supported value (2).
    #[error("fan_in_degree must be at least 2; got {0}")]
    InvalidFanIn(usize),

    /// `factor_values` and `factor_macs` lengths disagree at `product`.
    #[error("factor_values and factor_macs lengths disagree: values={values}, macs={macs}")]
    FactorLengthMismatch {
        /// Length of the `factor_values` slice.
        values: usize,
        /// Length of the `factor_macs` slice.
        macs: usize,
    },

    /// `product` was called with empty factor slices.
    #[error("product called with empty factor slices")]
    EmptyInput,
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_fields::gf2_128::Gf2_128;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::backend::ProverBackend;
    use mpz_vole_core::{
        RVOLEReceiver, RVOLESender,
        ideal::{
            rvole::{IdealRVOLEReceiver, ideal_rvole},
            rvope::IdealRVOPEReceiver,
        },
    };

    /// Build a prover-only backend with no pre-filled correlations.
    /// For tests that exercise bookkeeping.
    fn build_prover_only(
        rng_seed: u64,
        eps: usize,
    ) -> VoleZkProverBackend<
        Gf2_128,
        Gf2_128,
        IdealRVOLEReceiver<Gf2_128, Gf2_128>,
        IdealRVOPEReceiver<Gf2_128>,
    > {
        let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
        let delta: Gf2_128 = rng.random();
        let rvole_seed: u64 = rng.random();
        let rvope_seed: u64 = rng.random();
        let (_rvole_s, rvole_r) = ideal_rvole::<Gf2_128, Gf2_128>(rvole_seed, delta);
        let rvope_r = IdealRVOPEReceiver::<Gf2_128>::new(rvope_seed);
        VoleZkProverBackend::<Gf2_128, Gf2_128, _, _>::new(eps, rvole_r, rvope_r).unwrap()
    }

    /// Build a prover-only backend with RVOLE pre-filled.
    fn build_prover_with_correlations(
        rng_seed: u64,
        n: usize,
        eps: usize,
    ) -> VoleZkProverBackend<
        Gf2_128,
        Gf2_128,
        IdealRVOLEReceiver<Gf2_128, Gf2_128>,
        IdealRVOPEReceiver<Gf2_128>,
    > {
        let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
        let delta: Gf2_128 = rng.random();
        let rvole_seed: u64 = rng.random();
        let rvope_seed: u64 = rng.random();

        let rvole_count = 2 * fan_in_tree_internal_nodes(n, eps);
        let (mut rvole_s, mut rvole_r) = ideal_rvole::<Gf2_128, Gf2_128>(rvole_seed, delta);
        <_ as RVOLESender<Gf2_128>>::alloc(&mut rvole_s, rvole_count).unwrap();
        <_ as RVOLEReceiver<Gf2_128, Gf2_128>>::alloc(&mut rvole_r, rvole_count).unwrap();
        if let Some(msg) = rvole_s.flush() {
            rvole_r.flush(msg).unwrap();
        }

        let rvope_r = IdealRVOPEReceiver::<Gf2_128>::new(rvope_seed);
        VoleZkProverBackend::<Gf2_128, Gf2_128, _, _>::new(eps, rvole_r, rvope_r).unwrap()
    }

    /// Test cumulative-alloc contract.
    #[test]
    fn alloc_forwards_cumulative_deltas() {
        let mut prover = build_prover_only(0xE5, 8);
        assert_eq!(prover.rvoles_alloced(), 0);

        // running n=5  → internal_nodes(5,8)=1,  target=2, delta=+2
        prover.alloc(5).unwrap();
        assert_eq!(prover.rvoles_alloced(), 2);

        // running n=12 → internal_nodes(12,8)=2, target=4, delta=+2
        prover.alloc(7).unwrap();
        assert_eq!(prover.rvoles_alloced(), 4);

        // running n=16 → internal_nodes(16,8)=3, target=6, delta=+2
        prover.alloc(4).unwrap();
        assert_eq!(prover.rvoles_alloced(), 6);
    }

    /// Empty-input short-circuit.
    #[test]
    fn product_rejects_empty_input() {
        let mut prover = build_prover_only(0xE6, 8);
        let mut transcript = blake3::Hasher::new();
        let err = prover
            .product(&mut transcript, &[], &[])
            .expect_err("empty input must surface an error");
        assert!(
            matches!(err, VoleZkProverError::EmptyInput),
            "expected EmptyInput, got {err:?}"
        );
    }

    /// Singleton short-circuit.
    #[test]
    fn product_passes_through_singleton() {
        let mut prover = build_prover_only(0xE7, 8);
        let mut rng = ChaCha8Rng::seed_from_u64(0xE7_1234);
        let v: Gf2_128 = rng.random();
        let m: Gf2_128 = rng.random();

        let mut transcript = blake3::Hasher::new();
        let (ret_v, ret_m) = prover
            .product(&mut transcript, &[v], &[m])
            .expect("singleton passthrough must succeed");
        assert_eq!(ret_v, v);
        assert_eq!(ret_m, m);

        let prep = prover.drain_preparation().unwrap();
        assert!(
            prep.adjustments.is_empty(),
            "singleton passthrough must not buffer any adjustments"
        );
    }

    /// `product`'s root value must equal the total plaintext
    /// product of its input factors.
    #[test]
    fn product_computes_correct_root() {
        let cases = [
            (2, 2),   // minimal tree
            (10, 2),  // multi-level tight tree
            (10, 3),  // leftover=1 at leaves
            (10, 4),  // leftover=2 at leaves, padded
            (27, 3),  // clean power-of-3 tree, every level splits exactly
            (100, 8), // moderate size matching a pair-test shape
        ];

        for (n, eps) in cases {
            let mut prover = build_prover_with_correlations(
                0xF00D_u64.wrapping_add((n as u64) * 31 + eps as u64),
                n,
                eps,
            );

            let mut rng =
                ChaCha8Rng::seed_from_u64(0xBEEF_u64.wrapping_add((n as u64) * 17 + eps as u64));
            let values: Vec<Gf2_128> = (0..n).map(|_| rng.random()).collect();
            let macs: Vec<Gf2_128> = (0..n).map(|_| rng.random()).collect();

            prover.alloc(n).unwrap();
            let mut transcript = blake3::Hasher::new();
            let (prod_value, _prod_mac) = prover
                .product(&mut transcript, &values, &macs)
                .unwrap_or_else(|e| panic!("(n={n}, eps={eps}): {e:?}"));

            let expected = values
                .iter()
                .copied()
                .fold(Gf2_128::one(), |acc, x| acc * x);
            assert_eq!(
                prod_value, expected,
                "(n={n}, eps={eps}): root value must equal the total product"
            );
        }
    }
}
