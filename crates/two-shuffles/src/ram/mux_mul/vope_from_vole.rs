//! Lifted-VOLE-as-VOPE construction (degree-2 special case).
//!
//! A length-2 random VOPE is mathematically a single full-field IT-MAC viewed
//! as a polynomial in `Δ`:
//!
//! ```text
//! VOLE invariant:  m = k + v · Δ
//! VOPE relation:   sum = coeffs[0] + coeffs[1] · Δ
//!
//! Match:           coeffs = [m, -v],  sum = k.
//! ```

use mpz_fields::Field;
use mpz_poly_proof_core::{ExtensionField, ProverVope, VerifierVope};
use mpz_vole_core::{RVOLEReceiverOutput, RVOLESenderOutput};

/// Lift base VOLEs on the prover side into a length-2 [`ProverVope`].
///
/// # Panics
///
/// Panics if the number of VOLEs does not equal the extension degree.
pub fn prover_vope_from_vole<W, F>(vole: &RVOLEReceiverOutput<W, F>) -> ProverVope<F>
where
    W: Field,
    F: ExtensionField<W>,
{
    let basis = <F as ExtensionField<W>>::MONOMIAL_BASIS;
    let v_lifted: F = <F as ExtensionField<W>>::inner_product_subfield(&vole.values, basis);
    let m_lifted: F = F::inner_product(&vole.macs, basis);

    ProverVope {
        coeffs: vec![m_lifted, -v_lifted],
    }
}

/// Lift base VOLEs on the verifier side into a length-2 [`VerifierVope`].
///
/// # Panics
///
/// Panics if the number of VOLEs does not equal the extension degree.
pub fn verifier_vope_from_vole<W, F>(vole: &RVOLESenderOutput<F>) -> VerifierVope<F>
where
    W: Field,
    F: ExtensionField<W>,
{
    let basis = <F as ExtensionField<W>>::MONOMIAL_BASIS;
    let sum: F = F::inner_product(&vole.keys, basis);
    VerifierVope { sum }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use mpz_vole_core::{
        RVOLEReceiver, RVOLESender,
        ideal::rvole::ideal_rvole,
        test::{assert_vole, assert_vope},
    };
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// Pull paired RVOLE samples from the ideal functionality so the
    /// IT-MAC invariant holds by construction. Returns
    /// `(receiver_output, sender_output, delta)`.
    fn paired_samples(
        rng_seed: u64,
        n: usize,
    ) -> (
        RVOLEReceiverOutput<Gf2, Gf2_64>,
        RVOLESenderOutput<Gf2_64>,
        Gf2_64,
    ) {
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let delta: Gf2_64 = rng.random();
        let rvole_seed: u64 = rng.random();
        let (mut rvole_s, mut rvole_r) = ideal_rvole::<Gf2, Gf2_64>(rvole_seed, delta);
        rvole_s.pregenerate(n);
        rvole_r.pregenerate(n, delta).expect("rvole pregenerate");
        let recv = rvole_r.try_recv_vole(n).expect("try_recv_vole");
        let sender = rvole_s.try_send_vole(n).expect("try_send_vole");
        (recv, sender, delta)
    }

    /// Honest paired samples → resulting Vopes satisfy the
    /// length-2 VOPE relation: `sum = coeffs[0] + coeffs[1] · Δ`.
    /// Verified via `vole_core::test::assert_vope`.
    #[test]
    fn vope_invariant_holds_for_paired_samples() {
        let n = <Gf2_64 as ExtensionField<Gf2>>::MONOMIAL_BASIS.len();
        let (recv, sender, delta) = paired_samples(0xC0FFEE, n);

        // Sanity: ideal_rvole's output satisfies the IT-MAC invariant.
        assert_vole(delta, &sender.keys, &recv.values, &recv.macs);

        let p_vope = prover_vope_from_vole::<Gf2, _>(&recv);
        let v_vope = verifier_vope_from_vole::<Gf2, _>(&sender);

        // VOPE relation via the shared helper: sum equals the prover's
        // polynomial coeffs evaluated at Δ.
        assert_vope(delta, &[p_vope.coeffs], &[v_vope.sum]);
    }

    /// The prover-side Vope length is exactly `d_max = 2`.
    #[test]
    fn prover_vope_has_length_two() {
        let n = <Gf2_64 as ExtensionField<Gf2>>::MONOMIAL_BASIS.len();
        let (recv, _, _) = paired_samples(0xBEEF, n);
        let p_vope = prover_vope_from_vole::<Gf2, _>(&recv);
        assert_eq!(p_vope.coeffs.len(), 2);
    }

    /// Tampered key on the verifier side breaks the VOPE invariant.
    #[test]
    fn vope_invariant_fails_on_tampered_key() {
        let n = <Gf2_64 as ExtensionField<Gf2>>::MONOMIAL_BASIS.len();
        let (recv, mut sender, delta) = paired_samples(0xDEAD, n);
        // Tamper one key on the verifier side.
        sender.keys[7] = sender.keys[7] + Gf2_64::ONE;

        let p_vope = prover_vope_from_vole::<Gf2, _>(&recv);
        let v_vope = verifier_vope_from_vole::<Gf2, _>(&sender);

        // The shared `assert_vope` would panic; check directly.
        let reconstructed = p_vope.coeffs[0] + p_vope.coeffs[1] * delta;
        assert_ne!(
            v_vope.sum, reconstructed,
            "tampered key should break the VOPE invariant",
        );
    }
}
