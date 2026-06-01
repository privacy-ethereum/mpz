//! Mux-multiplication proof for the RAM private-op access.
//!
//! The RAM access multiplexer is `new = old + op·(w − old)`. This
//! module proves the `op · diff = prod` step (where `diff = w − old`)
//! across all accesses in a session, batched into a single QuickSilver
//! polynomial proof.

pub mod prover;
pub mod verifier;
pub mod vope_from_vole;

use mpz_circuits_new::Context;
use mpz_fields::{ExtensionField, Field};
use mpz_poly_proof_core::{
    ConstraintId, ConstraintsBuilder, ProofMessage, ProverConstraints, VerifierConstraints,
};
use mpz_poly_proof_macros::poly_kernel;
use mpz_vole_core::VoleAdjustment;

pub use prover::MuxMulProver;
pub use verifier::MuxMulVerifier;

/// A flush message.
///
/// The prover can emit this message at any time, letting the
/// verifier pipeline its computation rather than waiting until
/// teardown to process everything at once.
pub struct MuxMulFlush<F: Field> {
    /// One adjustment per [`MuxMulProver::accumulate`] call.
    pub adjustments: Vec<VoleAdjustment<F>>,
}

/// Closing message of the proof.
pub struct MuxMulProof<F: Field> {
    /// QS polynomial-proof message.
    pub qs_proof: ProofMessage<F>,
}

/// Draw a PRG seed from the transcript under a domain separation label.
pub(crate) fn draw_seed(transcript: &mut blake3::Hasher, label: &[u8]) -> [u8; 32] {
    transcript.update(label);
    let mut buf = [0u8; 32];
    transcript.finalize_xof().fill(&mut buf);
    buf
}

/// Mux mul-gate constraint: `a · x − c = 0` over `vars = [a, x, c]`.
/// `#[poly_kernel]` expands this into a `MulGate` `ConstraintDef`; the
/// re-emitted fn itself is scaffolding for the macro and isn't called
/// directly (only the generated `MulGate` type is used).
#[allow(dead_code)]
#[poly_kernel]
pub fn mul_gate<C, E>(ctx: &mut C, vars: [C::Wire; 3]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let prod = ctx.mul(vars[0], vars[1]);
    let diff = ctx.sub(prod, vars[2]);
    ctx.assert_const(diff, E::zero())
}

/// Booleanness constraint: `op · op − op = 0` over `vars = [op]`.
/// `#[poly_kernel]` expands this into a `BoolCheck` `ConstraintDef`; the
/// re-emitted fn itself is scaffolding for the macro and isn't called
/// directly (only the generated `BoolCheck` type is used).
#[allow(dead_code)]
#[poly_kernel]
pub fn bool_check<C, E>(ctx: &mut C, vars: [C::Wire; 1]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let sq = ctx.mul(vars[0], vars[0]);
    let diff = ctx.sub(sq, vars[0]);
    ctx.assert_const(diff, E::zero())
}

/// IDs of the constraints.
#[derive(Copy, Clone, Debug)]
pub(crate) struct MuxConstraintIds {
    /// Multiplication constraint: `a · b − c = 0`.
    pub mul: ConstraintId,
    /// Booleanness constraint: `op · op − op = 0`.
    ///
    /// Registered only when the caller requests it
    /// (typically skipped when the cleartext is already binary by
    /// type).
    pub bool_check: Option<ConstraintId>,
}

/// Build the QuickSilver constraint set used by the mux-mul protocol.
///
/// Returns both the prover- and verifier-side constraint tables (the
/// caller keeps the half it needs and drops the other) plus the
/// registered [`ConstraintId`]s.
pub(crate) fn build_mux_constraints<F, S>(
    boolean_check_enabled: bool,
) -> (
    ProverConstraints<F, S>,
    VerifierConstraints<F>,
    MuxConstraintIds,
)
where
    F: Field + ExtensionField<S>,
    S: Field,
{
    let mut b = ConstraintsBuilder::<F, S>::new();

    let mul = b
        .add::<MulGate>()
        .expect("mux mul-gate constraint registers");

    let bool_check = if boolean_check_enabled {
        let id = b
            .add::<BoolCheck>()
            .expect("mux boolean-check constraint registers");
        Some(id)
    } else {
        None
    };

    let (pc, vc) = b.build();
    (pc, vc, MuxConstraintIds { mul, bool_check })
}

#[cfg(test)]
mod tests {
    use super::{verifier::Error as VerifierError, *};
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use mpz_poly_proof_core::ExtensionField;
    use mpz_vole_core::ideal::rvole::ideal_rvole;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use crate::test_utils::commit_accesses;

    /// Per-access pattern element: `(op_value, diff_value)`.
    type Access = (Gf2, Vec<Gf2>);

    fn pattern() -> Vec<Access> {
        vec![
            (Gf2(true), bits4(0b1010)),
            (Gf2(false), bits4(0b0101)),
            (Gf2(true), bits4(0b1111)),
        ]
    }

    fn bits4(nibble: u8) -> Vec<Gf2> {
        use itybity::{FromBitIterator, ToBits};
        Vec::<Gf2>::from_lsb0_iter(nibble.iter_lsb0().take(4))
    }

    /// Drive the full mux-mul prover↔verifier flow.
    fn run(tamper: TamperKind) -> Result<(), VerifierError> {
        let mut rng = StdRng::seed_from_u64(0x42);
        let delta: Gf2_64 = rng.random();
        let vope_rvole_seed: u64 = rng.random();
        let mul_rvole_seed: u64 = rng.random();

        let pattern = pattern();
        let n_accesses = pattern.len();
        let l_val = pattern[0].1.len();
        let num_mul_gates = n_accesses * l_val;
        // VOPE-side pool: `EXTENSION_DEGREE` base VOLEs for the
        // lifted-VOPE at finalize.
        let vope_count = <Gf2_64 as ExtensionField<Gf2>>::MONOMIAL_BASIS.len();
        let (mut vope_rvole_s, mut vope_rvole_r) =
            ideal_rvole::<Gf2, Gf2_64>(vope_rvole_seed, delta);
        vope_rvole_s.pregenerate(vope_count);
        vope_rvole_r
            .pregenerate(vope_count, delta)
            .expect("vope rvole pregenerate");

        // Mul-gate-side pool: one RVOLE per prod-wire commit.
        let (mut mul_rvole_s, mut mul_rvole_r) = ideal_rvole::<Gf2, Gf2_64>(mul_rvole_seed, delta);
        mul_rvole_s.pregenerate(num_mul_gates);
        mul_rvole_r
            .pregenerate(num_mul_gates, delta)
            .expect("mul rvole pregenerate");
        let prover_mul_vole = mpz_vole_core::DerandVOLEReceiver::new(mul_rvole_r);

        // Pack each access as an (op, diff) 2-tuple and commit them.
        let access_tuples: Vec<[Vec<Gf2>; 2]> = pattern
            .into_iter()
            .map(|(op_val, diff_val)| [vec![op_val], diff_val])
            .collect();
        let (access_commits, transcript) =
            commit_accesses::<Gf2, Gf2_64, 2>(access_tuples, delta, &mut rng);

        // Each side gets its own transcript — they start identical.
        let mut p_transcript = transcript.clone();
        let mut v_transcript = transcript;

        // All input-side tampering happens here.
        if let TamperKind::WrongTranscript = tamper {
            v_transcript.update(b"diverge");
        }
        let v_ops: Vec<crate::wire::VerifierWire<Gf2_64>> = access_commits
            .iter()
            .map(|[(_, v_op), _]| {
                let k = match tamper {
                    TamperKind::WrongOpKey => v_op.key[0] + Gf2_64::ONE,
                    _ => v_op.key[0],
                };
                crate::wire::VerifierWire::new(crate::wire::Bundle::new(vec![k]))
            })
            .collect();
        let v_diffs: Vec<crate::wire::VerifierWire<Gf2_64>> = access_commits
            .iter()
            .map(|[_, (_, v_diff)]| v_diff.clone())
            .collect();

        // Gf2 has BIT_SIZE = 1 → no boolean check.
        let verifier_mul_vole = mpz_vole_core::DerandVOLESender::new(mul_rvole_s);
        let mut prover =
            MuxMulProver::<_, _, Gf2, Gf2_64>::new(vope_rvole_r, prover_mul_vole, false);
        let mut verifier =
            MuxMulVerifier::<_, _, Gf2, Gf2_64>::new(vope_rvole_s, verifier_mul_vole, false);

        prover.alloc(num_mul_gates).expect("prover alloc");
        verifier.alloc(num_mul_gates).expect("verifier alloc");

        // Prover phase.
        for [(p_op, _), (p_diff, _)] in &access_commits {
            prover.accumulate(p_op, p_diff).expect("accumulate");
        }
        let flush = prover.flush().expect("flush");
        let MuxMulProof { mut qs_proof } =
            prover.finalize(&mut p_transcript).expect("prover finalize");

        // Transport tamper: corrupt the proof in flight.
        if let TamperKind::FlipProofCoeff = tamper {
            let c = qs_proof.coefficients[0];
            qs_proof.coefficients[0] = c + Gf2_64::ONE;
        }

        // Verifier phase.
        assert_eq!(flush.adjustments.len(), n_accesses);
        verifier
            .accumulate(&v_ops, &v_diffs, &flush)
            .expect("accumulate");
        verifier.finalize(&mut v_transcript, &qs_proof)
    }

    #[derive(Copy, Clone)]
    enum TamperKind {
        /// No tampering — the protocol should accept.
        None,
        /// Verifier's transcript diverges from the prover's; the QS
        /// seed drawn at finalize will differ.
        WrongTranscript,
        /// Verifier sees the wrong key for `op` on every batched
        /// access.
        WrongOpKey,
        /// One coefficient of the proof message gets one bit flipped.
        FlipProofCoeff,
    }

    #[test]
    fn accepts_honest() {
        run(TamperKind::None).expect("honest must accept");
    }

    #[test]
    fn rejects_mismatched_transcript() {
        let err = run(TamperKind::WrongTranscript).expect_err("mismatched transcript must reject");
        assert!(
            matches!(err, VerifierError::Qs(_)),
            "expected Qs error, got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_op_key() {
        let err = run(TamperKind::WrongOpKey).expect_err("wrong op_key must reject");
        assert!(
            matches!(err, VerifierError::Qs(_)),
            "expected Qs error, got {err:?}"
        );
    }

    #[test]
    fn rejects_flipped_proof_coeff() {
        let err = run(TamperKind::FlipProofCoeff).expect_err("flipped proof coeff must reject");
        assert!(
            matches!(err, VerifierError::Qs(_)),
            "expected Qs error, got {err:?}"
        );
    }
}
