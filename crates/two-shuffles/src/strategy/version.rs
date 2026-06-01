//! Version-chain step rules.
//!
//! Protocols that maintain a per-key version counter advance it by one
//! step on every access. This
//! module defines what "one step" means.

use mpz_fields::{Field, gf2::Gf2};

use super::{Char2, IntegerLike};
use mpz_poly_proof_core::ExtensionField;

use crate::{
    gf2n::{GfMulMatrix, field_constants},
    wire::{ProverWire, VerifierWire},
};

pub use crate::gf2n::UnsupportedDegree;

// ---------------------------------------------------------------------------
// Trait hierarchy
// ---------------------------------------------------------------------------

/// Common base: wire length of every version-chain wire under this
/// strategy.
pub trait VersionStep<S> {
    /// Wire length of every version wire under this strategy.
    fn len(&self) -> usize;

    /// Maximum number of `next()` advances before the version chain
    /// cycles back to the anchor. Callers must ensure that the
    /// per-key access count never exceeds this — otherwise two
    /// distinct lookups would commit to the same version slot,
    /// breaking the protocol's soundness.
    ///
    /// Returned as `u64` so the bound stays representable on 32-bit
    /// targets (where `usize::MAX < u64::MAX`).
    fn max_advances(&self) -> u64;
}

/// Prover-side: advance the authenticated wire to the next version.
pub trait ProverVersionStep<S, F>: VersionStep<S>
where
    S: Field,
    F: ExtensionField<S>,
{
    /// Anchor wire — the public-constant initial version.
    fn anchor(&self) -> ProverWire<S, F>;

    /// Compute the next version wire from the current one.
    fn next(&mut self, current: &ProverWire<S, F>) -> ProverWire<S, F>;
}

/// Verifier-side advance the authenticated wire to the next version.
pub trait VerifierVersionStep<S, F>: VersionStep<S>
where
    S: Field,
    F: ExtensionField<S>,
{
    /// Anchor wire — the public-constant initial version.
    fn anchor(&self, delta: F) -> VerifierWire<F>;

    /// Compute the next version wire from the current one.
    fn next(&mut self, current: &VerifierWire<F>, delta: F) -> VerifierWire<F>;
}

// ---------------------------------------------------------------------------
// AdditiveStep
// ---------------------------------------------------------------------------

/// Additive version-chain step rule for length-1 wires.
///
/// The next version is `current + 1`. The MAC is unchanged because
/// adding a public constant has zero MAC contribution.
pub struct AdditiveStep;

impl<S> VersionStep<S> for AdditiveStep
where
    S: Field + IntegerLike,
{
    fn len(&self) -> usize {
        1
    }

    fn max_advances(&self) -> u64 {
        // TODO: add `const ORDER` to the `Field` trait and use
        // that here.
        u32::MAX as u64
    }
}

impl<S, F> ProverVersionStep<S, F> for AdditiveStep
where
    S: Field + IntegerLike,
    F: ExtensionField<S>,
{
    fn anchor(&self) -> ProverWire<S, F> {
        // Anchor at zero — the additive identity.
        ProverWire::constant(S::zero())
    }

    fn next(&mut self, current: &ProverWire<S, F>) -> ProverWire<S, F> {
        assert_eq!(current.len(), 1, "AdditiveStep operates on length-1 wires",);
        ProverWire::new(
            (current.value()[0] + S::one()).into(),
            current.mac().clone(), // MAC unchanged for "+ public constant".
        )
    }
}

impl<S, F> VerifierVersionStep<S, F> for AdditiveStep
where
    S: Field + IntegerLike,
    F: ExtensionField<S>,
{
    fn anchor(&self, delta: F) -> VerifierWire<F> {
        // Anchor at zero — the additive identity.
        VerifierWire::constant(&[S::zero()], delta)
    }

    fn next(&mut self, current: &VerifierWire<F>, delta: F) -> VerifierWire<F> {
        assert_eq!(current.len(), 1, "AdditiveStep operates on length-1 wires",);
        // Adding `+1` keeps the prover's MAC unchanged but shifts
        // K by −Δ · 1.embed() = −Δ on the verifier side.
        (current.key[0] - delta).into()
    }
}

// ---------------------------------------------------------------------------
// MultiplicativeStep
// ---------------------------------------------------------------------------

/// Multiplicative version-chain step rule for GF2 wires.
///
/// Treats `[Gf2; N]` as an element of `GF(2^N)` under a fixed primitive
/// polynomial; the next version is `current · g` where `g` is the
/// multiplicative generator.
pub struct MultiplicativeStep {
    /// Pre-computed `· g` matrix.
    matrix: GfMulMatrix,
    /// Order of `g` in `GF(2^N)`'s multiplicative group (`2^N − 1`).
    group_order: u64,
}

impl MultiplicativeStep {
    /// Construct a step rule sized to support at least `num_steps`
    /// advances.
    pub fn new(num_steps: usize) -> Result<Self, MulStepError> {
        let n = smallest_degree_for(num_steps).ok_or(MulStepError::TooManySteps(num_steps))?;
        let c = field_constants(n).expect("smallest_degree_for returns a supported degree");
        Ok(Self {
            matrix: GfMulMatrix::new(c.poly, c.generator, n),
            group_order: c.group_order,
        })
    }

    /// Bit pattern of `1 ∈ GF(2^N)` — the multiplicative identity.
    fn anchor(&self) -> Vec<Gf2> {
        let mut a = vec![Gf2::ZERO; self.matrix.len()];
        a[0] = Gf2::ONE;
        a
    }
}

/// Smallest supported degree whose multiplicative group admits `num_steps`
/// advances without cycling.
fn smallest_degree_for(num_steps: usize) -> Option<usize> {
    (8..=26).find(|&n| (1u64 << n) >= num_steps as u64 + 2)
}

/// Construction error for [`MultiplicativeStep`].
#[derive(Debug, thiserror::Error)]
pub enum MulStepError {
    /// `num_steps` exceeds the largest supported version chain
    /// (`2^26 − 2`).
    #[error("num_steps {0} exceeds the largest supported version chain (2^26 - 2)")]
    TooManySteps(usize),
}

impl VersionStep<Gf2> for MultiplicativeStep {
    fn len(&self) -> usize {
        self.matrix.len()
    }

    fn max_advances(&self) -> u64 {
        self.group_order - 1
    }
}

impl<F> ProverVersionStep<Gf2, F> for MultiplicativeStep
where
    F: Char2 + ExtensionField<Gf2>,
{
    fn anchor(&self) -> ProverWire<Gf2, F> {
        ProverWire::constant(self.anchor())
    }

    fn next(&mut self, current: &ProverWire<Gf2, F>) -> ProverWire<Gf2, F> {
        // Cleartext bits and MAC bundle both advance via the same
        // `· g` linear map.
        let next_value = self.matrix.apply(current.value());
        let next_mac = self.matrix.apply_lifted(current.mac());
        ProverWire::new(next_value.into(), next_mac.into())
    }
}

impl<F> VerifierVersionStep<Gf2, F> for MultiplicativeStep
where
    F: Char2 + ExtensionField<Gf2>,
{
    fn anchor(&self, delta: F) -> VerifierWire<F> {
        VerifierWire::constant(&self.anchor(), delta)
    }

    fn next(&mut self, current: &VerifierWire<F>, _delta: F) -> VerifierWire<F> {
        // No Δ-adjustment needed (pure linear `· g`): key updates with
        // the same matrix as MAC.
        self.matrix.apply_lifted(&current.key).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{bits, pow_mod},
        wire::Bundle,
    };
    use mpz_fields::gf2_64::Gf2_64;
    use mpz_vole_core::test::assert_vole;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// The anchor is `1 ∈ GF(2^n)` (the multiplicative identity).
    #[test]
    fn mul_step_anchor_is_one() {
        let step = MultiplicativeStep::new(50).expect("step");
        let n = VersionStep::<Gf2>::len(&step);
        let anchor = <MultiplicativeStep as ProverVersionStep<Gf2, Gf2_64>>::anchor(&step);
        assert_eq!(anchor.value().as_slice(), bits(1, n).as_slice());
    }

    /// `new(num_steps)` picks the smallest field whose group admits
    /// `num_steps` advances (`max_advances = 2^len − 2 >= num_steps`),
    /// and rejects counts beyond the largest supported field.
    #[test]
    fn mul_step_sizes_to_num_steps() {
        // Degree floor is 8 (group order 255 ⇒ max_advances 254).
        let s = MultiplicativeStep::new(0).expect("step");
        assert_eq!(VersionStep::<Gf2>::len(&s), 8);
        assert_eq!(VersionStep::<Gf2>::max_advances(&s), (1u64 << 8) - 2);

        // 254 still fits degree 8; 255 needs degree 9.
        assert_eq!(
            VersionStep::<Gf2>::len(&MultiplicativeStep::new(254).unwrap()),
            8
        );
        assert_eq!(
            VersionStep::<Gf2>::len(&MultiplicativeStep::new(255).unwrap()),
            9
        );

        // Every result satisfies the cycle bound it was sized for.
        for num_steps in [300usize, 5_000, 100_000] {
            let s = MultiplicativeStep::new(num_steps).expect("step");
            assert!(VersionStep::<Gf2>::max_advances(&s) >= num_steps as u64);
        }

        // Beyond the largest supported field (2^26 − 2) → error.
        assert!(MultiplicativeStep::new((1 << 26) - 1).is_err());
    }

    /// Advancing the anchor `k` times yields `g^k` — the version chain
    /// walks the multiplicative group.
    #[test]
    fn mul_step_next_tracks_g_powers() {
        let mut step = MultiplicativeStep::new(50).expect("step");
        let n = VersionStep::<Gf2>::len(&step);
        let c = field_constants(n).expect("constants");

        let mut cur = <MultiplicativeStep as ProverVersionStep<Gf2, Gf2_64>>::anchor(&step);
        for k in 1..=50u64 {
            cur = <MultiplicativeStep as ProverVersionStep<Gf2, Gf2_64>>::next(&mut step, &cur);
            let expected = pow_mod(c.generator, k, c.poly, n);
            assert_eq!(
                cur.value().as_slice(),
                bits(expected, n).as_slice(),
                "g^{k}"
            );
        }
    }

    /// `next` preserves the IT-MAC relation.
    #[test]
    fn mul_step_next_preserves_itmac() {
        let mut step = MultiplicativeStep::new(50).expect("step");
        let n = VersionStep::<Gf2>::len(&step);
        let c = field_constants(n).expect("constants");
        let mut rng = StdRng::seed_from_u64(0x5715);
        let delta: Gf2_64 = rng.random();

        // An authenticated current version (a valid power, g^5).
        let value = bits(pow_mod(c.generator, 5, c.poly, n), n);
        let keys: Vec<Gf2_64> = (0..n).map(|_| rng.random()).collect();
        let macs: Vec<Gf2_64> = value
            .iter()
            .zip(&keys)
            .map(|(v, k)| *k + delta * <Gf2_64 as ExtensionField<Gf2>>::embed(*v))
            .collect();

        let p_cur = ProverWire::new(Bundle::new(value), Bundle::new(macs));
        let v_cur = VerifierWire::new(Bundle::new(keys));

        let p_next =
            <MultiplicativeStep as ProverVersionStep<Gf2, Gf2_64>>::next(&mut step, &p_cur);
        let v_next = <MultiplicativeStep as VerifierVersionStep<Gf2, Gf2_64>>::next(
            &mut step, &v_cur, delta,
        );

        assert_vole(
            delta,
            v_next.key.as_slice(),
            p_next.value().as_slice(),
            p_next.mac().as_slice(),
        );
    }
}
