//! Quicksilver-specific evaluators for the straight-line (kernel)
//! representation of a multivariate constraint polynomial.

use crate::{ExtensionField, Field};

/// Prover-side kernel for a single constraint.
pub trait ProverKernel<E: Field, W: Field>
where
    E: ExtensionField<W>,
{
    /// Number of input variables this kernel expects.
    const NUM_VARS: usize;

    /// Polynomial degree this kernel produces.
    const DEGREE: usize;

    /// Accumulate this constraint's polynomial contribution into the
    /// prover's running coefficient vector.
    ///
    /// # Arguments
    ///
    /// * `macs` - Per-variable MACs. Length must equal
    ///   [`NUM_VARS`](Self::NUM_VARS).
    /// * `values` - Per-variable witness values. Length must equal
    ///   [`NUM_VARS`](Self::NUM_VARS).
    /// * `chi` - The Fiat-Shamir-derived weight for this evaluation.
    /// * `accumulators` - The prover's running coefficient vector (length
    ///   `d_max`).
    fn accumulate(macs: &[E], values: &[W], chi: E, accumulators: &mut [E]);
}

/// Verifier-side kernel for a single constraint.
pub trait VerifierKernel<E: Field> {
    /// Number of input keys this kernel expects.
    const NUM_VARS: usize;

    /// Polynomial degree this kernel produces.
    const DEGREE: usize;

    /// Evaluate the constraint polynomial at Δ using the verifier's
    /// keys.
    ///
    /// # Arguments
    ///
    /// * `keys` - One MAC key per input variable. Length must equal
    ///   [`NUM_VARS`](Self::NUM_VARS).
    /// * `delta_pow` - Precomputed powers of Δ, with `delta_pow[k] == Δ^k`.
    ///   Populated up to at least `delta_pow[DEGREE]`.
    ///
    /// # Returns
    ///
    /// The constraint polynomial evaluated at Δ, at the constraint's
    /// own degree `DEGREE`.
    fn evaluate(keys: &[E], delta_pow: &[E]) -> E;
}

/// Bundles a constraint's prover and verifier kernels with its shape
/// under one registration-friendly type.
pub trait ConstraintDef<E: Field, W: Field>
where
    E: ExtensionField<W>,
{
    /// Number of input variables.
    const NUM_VARS: usize;

    /// Polynomial degree of the constraint.
    const DEGREE: usize;

    /// Prover-side kernel for this constraint.
    type ProverKernel: ProverKernel<E, W>;

    /// Verifier-side kernel for this constraint.
    type VerifierKernel: VerifierKernel<E>;
}

#[cfg(test)]
mod tests {
    use super::{ConstraintDef, ProverKernel, VerifierKernel};
    use crate::{
        fixture::{
            AccMux, AddrBaseMux, AddrIndexMux, CarryChain, CarryGenerate, Coverage, FpMux,
            MulBitExtraction, MulForce, PcMux, SpMux, WriteBack, WriteBackBit0, coverage,
        },
        test_utils::{PolyOracle, eval_at},
    };
    use mpz_circuits_new::fixtures::{
        acc_mux, addr_base_mux, addr_index_mux, carry_chain, carry_generate, fp_mux,
        mul_bit_extraction, mul_force, pc_mux, sp_mux, write_back, write_back_bit0,
    };
    use mpz_fields::{ExtensionField, Field, gf2::Gf2, gf2_64::Gf2_64};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// Differential check: the emitted [`ProverKernel`] / [`VerifierKernel`]
    /// for `C` must agree, over random authenticated witnesses.
    fn check<C, F>(rng: &mut StdRng, delta: Gf2_64, run: F)
    where
        C: ConstraintDef<Gf2_64, Gf2>,
        F: Fn(&mut PolyOracle<Gf2_64>, &[usize]) -> Result<(), ()>,
    {
        let name = std::any::type_name::<C>();
        let n = C::NUM_VARS;
        let d = C::DEGREE;

        // Δ-power table sized for this constraint's degree.
        let mut delta_pow = vec![Gf2_64::one(); d + 1];
        for k in 1..=d {
            delta_pow[k] = delta_pow[k - 1] * delta;
        }

        for _ in 0..16 {
            // Random authenticated witness: key = mac + value·Δ.
            let values: Vec<Gf2> = (0..n).map(|_| Gf2(rng.random::<bool>())).collect();
            let macs: Vec<Gf2_64> = (0..n).map(|_| Gf2_64(rng.random::<u64>())).collect();
            let keys: Vec<Gf2_64> = (0..n)
                .map(|i| macs[i] + Gf2_64::embed(values[i]) * delta)
                .collect();

            // Oracle: run the constraint fn over `mac + value·X` wires,
            // recover the constraint polynomial Q(X) (low degree first).
            let mut oracle = PolyOracle::<Gf2_64>::new();
            let wires: Vec<usize> = (0..n)
                .map(|i| oracle.push_var(macs[i], Gf2_64::embed(values[i])))
                .collect();
            run(&mut oracle, &wires).expect("oracle constraint run");
            let q = oracle.into_output();
            assert_eq!(
                q.len(),
                d + 1,
                "{name}: oracle degree disagrees with DEGREE"
            );

            // Verifier side: Q(Δ) == kernel.evaluate(keys, delta_pow).
            let oracle_at_delta = eval_at(&q, delta);
            let verifier_out =
                <C::VerifierKernel as VerifierKernel<Gf2_64>>::evaluate(&keys, &delta_pow);
            assert_eq!(
                oracle_at_delta, verifier_out,
                "{name}: verifier kernel disagrees with oracle at Δ"
            );

            // Prover side: the bottom `d` coefficients (the top one is the
            // protocol's dropped coefficient) == the χ=1 accumulator.
            let mut acc = vec![Gf2_64::zero(); d];
            <C::ProverKernel as ProverKernel<Gf2_64, Gf2>>::accumulate(
                &macs,
                &values,
                Gf2_64::one(),
                &mut acc,
            );
            for k in 0..d {
                assert_eq!(
                    acc[k], q[k],
                    "{name}: prover kernel coefficient {k} disagrees with oracle"
                );
            }
        }
    }

    #[test]
    fn kernels_match_poly_oracle() {
        let mut rng = StdRng::seed_from_u64(0xD1FF_C0DE_u64);
        let delta = Gf2_64(rng.random::<u64>());

        // Coverage constraint.
        check::<Coverage, _>(&mut rng, delta, |c, v| coverage(c, v.try_into().unwrap()));

        // The 12 fixture constraints.
        check::<CarryGenerate, _>(&mut rng, delta, |c, v| {
            carry_generate(c, v.try_into().unwrap())
        });
        check::<CarryChain, _>(&mut rng, delta, |c, v| {
            carry_chain(c, v.try_into().unwrap())
        });
        check::<WriteBack, _>(&mut rng, delta, |c, v| write_back(c, v.try_into().unwrap()));
        check::<WriteBackBit0, _>(&mut rng, delta, |c, v| {
            write_back_bit0(c, v.try_into().unwrap())
        });
        check::<AddrBaseMux, _>(&mut rng, delta, |c, v| {
            addr_base_mux(c, v.try_into().unwrap())
        });
        check::<AddrIndexMux, _>(&mut rng, delta, |c, v| {
            addr_index_mux(c, v.try_into().unwrap())
        });
        check::<MulBitExtraction, _>(&mut rng, delta, |c, v| {
            mul_bit_extraction(c, v.try_into().unwrap())
        });
        check::<MulForce, _>(&mut rng, delta, |c, v| mul_force(c, v.try_into().unwrap()));
        check::<AccMux, _>(&mut rng, delta, |c, v| acc_mux(c, v.try_into().unwrap()));
        check::<PcMux, _>(&mut rng, delta, |c, v| pc_mux(c, v.try_into().unwrap()));
        check::<SpMux, _>(&mut rng, delta, |c, v| sp_mux(c, v.try_into().unwrap()));
        check::<FpMux, _>(&mut rng, delta, |c, v| fp_mux(c, v.try_into().unwrap()));
    }
}
