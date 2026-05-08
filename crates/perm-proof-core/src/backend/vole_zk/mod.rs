//! VOLE-ZK backend (prover and verifier) built on top of VOLE-ZK
//! authentication with a QuickSilver polynomial proof for fan-in
//! multiplications.

use mpz_circuits_new::Context;
use mpz_fields::Field;
use mpz_poly_proof_core::{ConstraintId, Constraints};

pub mod prover;
pub mod verifier;

pub use prover::{Preparation, Proof, VoleZkProverBackend, VoleZkProverError};
pub use verifier::{VoleZkVerifierBackend, VoleZkVerifierError};

/// Internal-node count of a fan-in-`d` tree over `n` leaves —
/// `⌈(n−1)/(d−1)⌉`, since each merge takes `d` items into 1 and
/// reducing `n` to `1` requires `n−1` removals.
pub(crate) fn fan_in_tree_internal_nodes(n: usize, d: usize) -> usize {
    n.saturating_sub(1).div_ceil(d - 1)
}

/// Split `[0, n)` into `d`-sized chunks plus the trailing leftover.
pub(crate) fn chunk_ranges_and_leftover(n: usize, d: usize) -> (Vec<(usize, usize)>, Vec<usize>) {
    let full = n / d;
    let chunks: Vec<(usize, usize)> = (0..full).map(|i| (i * d, (i + 1) * d)).collect();
    let leftover: Vec<usize> = (full * d..n).collect();
    (chunks, leftover)
}

/// Build a `Constraints` set holding the single fan-in-product
/// constraint `(x_0 · x_1 · … · x_{n-1}) − prod = 0`.
///
/// Variable layout: `var(0)…var(n−1)` are the factors, `var(n)` is
/// `prod`. Returns the set alongside the constraint's id.
pub(crate) fn build_product_constraints<E: Field>(
    factor_count: usize,
) -> (Constraints<E>, ConstraintId) {
    assert!(factor_count >= 1);
    let mut b = Constraints::<E>::builder();
    let id = b
        .add_dynamic(factor_count + 1, |ctx, vars| {
            // `add_dynamic(factor_count + 1, …)` allocates exactly that
            // many wires, so the indices below are always in bounds.
            let mut product = vars[0];
            for &f in &vars[1..factor_count] {
                product = ctx.mul(product, f);
            }
            ctx.assert_eq(product, vars[factor_count])
        })
        .expect("product constraint shape is well-formed");
    (b.build(), id)
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_fields::gf2_128::Gf2_128;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use crate::{
        backend::{ProverBackend, VerifierBackend},
        test_utils::{Committed, commit_values},
    };
    use mpz_vole_core::{
        RVOLEReceiver, RVOLESender, RVOPEReceiver, RVOPESender,
        ideal::{
            rvole::{IdealRVOLEReceiver, IdealRVOLESender, ideal_rvole},
            rvope::{IdealRVOPEReceiver, IdealRVOPESender, ideal_rvope},
        },
    };

    /// Build both VOLE-ZK backends wired to pre-filled ideal correlation
    /// providers, sized for a proof of running size `n` with fan-in `eps`.
    fn build_pair(
        rng_seed: u64,
        n: usize,
        eps: usize,
    ) -> (
        Gf2_128,
        VoleZkProverBackend<
            Gf2_128,
            Gf2_128,
            IdealRVOLEReceiver<Gf2_128, Gf2_128>,
            IdealRVOPEReceiver<Gf2_128>,
        >,
        VoleZkVerifierBackend<
            Gf2_128,
            Gf2_128,
            IdealRVOLESender<Gf2_128>,
            IdealRVOPESender<Gf2_128>,
        >,
    ) {
        let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
        let delta: Gf2_128 = rng.random();
        let rvole_seed: u64 = rng.random();
        let rvope_seed: u64 = rng.random();

        // Match what the backend's own `alloc` reserves.
        let rvole_count = 2 * fan_in_tree_internal_nodes(n, eps);
        let (mut rvole_s, mut rvole_r) = ideal_rvole::<Gf2_128, Gf2_128>(rvole_seed, delta);
        <_ as RVOLESender<Gf2_128>>::alloc(&mut rvole_s, rvole_count).unwrap();
        <_ as RVOLEReceiver<Gf2_128, Gf2_128>>::alloc(&mut rvole_r, rvole_count).unwrap();
        if let Some(msg) = rvole_s.flush() {
            rvole_r.flush(msg).unwrap();
        }

        // Pre-fill RVOPE — query a throwaway QS prover.
        let (constraints, _) = build_product_constraints::<Gf2_128>(eps);
        let tmp_qs = mpz_poly_proof_core::prover::Prover::<Gf2_128>::new(&constraints);
        let required_vopes = tmp_qs.required_vopes();

        let (mut rvope_s, mut rvope_r) = ideal_rvope::<Gf2_128>(rvope_seed, delta);
        <_ as RVOPESender<Gf2_128>>::alloc(&mut rvope_s, 1, required_vopes).unwrap();
        <_ as RVOPEReceiver<Gf2_128>>::alloc(&mut rvope_r, 1, required_vopes).unwrap();
        for msg in rvope_s.flush() {
            rvope_r.flush(msg).unwrap();
        }

        let prover =
            VoleZkProverBackend::<Gf2_128, Gf2_128, _, _>::new(eps, rvole_r, rvope_r).unwrap();
        let verifier =
            VoleZkVerifierBackend::<Gf2_128, Gf2_128, _, _>::new(eps, delta, rvole_s, rvope_s)
                .unwrap();

        (delta, prover, verifier)
    }

    /// Mode toggle for [`run_pair`].
    #[derive(Clone, Copy)]
    enum Mode {
        /// Honest prover.
        Honest,
        /// Dishonest prover.
        Dishonest,
    }

    /// Drive a prover/verifier pair through the full backend lifecycle
    /// against `n` factors with fan-in `eps`.
    fn run_pair(
        rng_seed: u64,
        n: usize,
        eps: usize,
        mode: Mode,
    ) -> Result<(), VoleZkVerifierError> {
        let (delta, mut prover, mut verifier) = build_pair(rng_seed, n, eps);

        let mut rng = ChaCha8Rng::seed_from_u64(rng_seed ^ 0xABCD_EF01);
        // Width-1 tuples: each position is a singleton Vec.
        let mut values: Vec<Vec<Gf2_128>> = (0..n).map(|_| vec![rng.random()]).collect();
        let Committed {
            macs: [macs],
            keys: [keys],
            transcript,
        } = commit_values([&values[..]], delta, &mut rng);

        // Tamper AFTER authentication.
        if matches!(mode, Mode::Dishonest) {
            values[0][0] = values[0][0] + Gf2_128::one();
        }

        prover.alloc(n).unwrap();
        verifier.alloc(n).unwrap();

        // Transcript is bound to committed values.
        let mut tp = transcript.clone();
        let mut tv = transcript;

        // Flatten width-1 tuples into plain slices for the backend.
        let flat_values: Vec<Gf2_128> = values.iter().flatten().copied().collect();
        let flat_macs: Vec<Gf2_128> = macs.iter().flatten().copied().collect();
        let flat_keys: Vec<Gf2_128> = keys.iter().flatten().copied().collect();

        let (prod_value, prod_mac) = prover.product(&mut tp, &flat_values, &flat_macs).unwrap();
        let prep = prover.drain_preparation().unwrap();
        verifier.load_preparation(prep);
        let prod_key = verifier.product(&mut tv, &flat_keys).unwrap();

        if matches!(mode, Mode::Honest) {
            assert_eq!(
                prod_mac,
                prod_key + delta * prod_value,
                "IT-MAC invariant violated at fan-in-product root"
            );
        }

        let proof = prover.prove().unwrap();
        verifier.verify(proof)
    }

    /// Honest prover: each shape exercises a different path through the
    /// fan-in tree.
    #[test]
    fn accepts() {
        // Multi-level walk with leftover passthroughs and a terminal short chunk.
        run_pair(0xA1, 100, 8, Mode::Honest).expect("honest must accept");
        // ε=2: tightest tree, many small levels.
        run_pair(0xC3, 9, 2, Mode::Honest).expect("honest must accept");
        // n == ε: one-level tree, single chunk, no leftover.
        run_pair(0xD4, 4, 4, Mode::Honest).expect("honest must accept");
    }

    /// Dishonest prover: tampered input is rejected.
    #[test]
    fn rejects_tampered_input() {
        let err =
            run_pair(0xA1, 100, 8, Mode::Dishonest).expect_err("tampered input must be rejected");
        assert!(
            matches!(err, VoleZkVerifierError::QsVerify(_)),
            "expected QsVerify, got {err:?}"
        );
    }

    #[test]
    fn test_fan_in_tree_internal_nodes() {
        assert_eq!(fan_in_tree_internal_nodes(1, 2), 0); // single leaf, no merge
        assert_eq!(fan_in_tree_internal_nodes(8, 2), 7); // 8-leaf binary tree
        assert_eq!(fan_in_tree_internal_nodes(8, 8), 1); // one merge of all 8
        assert_eq!(fan_in_tree_internal_nodes(9, 8), 2); // 8 merge + 2-merge
    }

    #[test]
    fn test_chunk_ranges_and_leftover() {
        // Clean split: n is a multiple of d.
        assert_eq!(
            chunk_ranges_and_leftover(8, 4),
            (vec![(0, 4), (4, 8)], vec![])
        );
        // Two full chunks + trailing leftover.
        assert_eq!(
            chunk_ranges_and_leftover(10, 4),
            (vec![(0, 4), (4, 8)], vec![8, 9])
        );
        // n < d: no full chunk fits, everything is leftover.
        assert_eq!(chunk_ranges_and_leftover(3, 4), (vec![], vec![0, 1, 2]));
        // Single index → single leftover.
        assert_eq!(chunk_ranges_and_leftover(1, 4), (vec![], vec![0]));
    }
}
