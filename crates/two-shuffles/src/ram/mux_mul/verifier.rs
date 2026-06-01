//! Verifier side of the mux-multiplication protocol.
use mpz_fields::Field;
use mpz_poly_proof_core::{ExtensionField, ProofMessage, verifier::Verifier as QsVerifier};
use mpz_vole_core::{DerandVOLESender, DerandVOLESenderError, RVOLESender};
use zerocopy::{FromBytes, IntoBytes};

use crate::wire::VerifierWire as Wire;

use super::{
    MuxConstraintIds, MuxMulFlush, build_mux_constraints, vope_from_vole::verifier_vope_from_vole,
};

/// Mux-multiplication verifier.
pub struct MuxMulVerifier<RV, RM, S, F>
where
    RV: RVOLESender<F>,
    RM: RVOLESender<F>,
    S: Field,
    F: ExtensionField<S>,
{
    /// QuickSilver polynomial protocol verifier.
    qs: QsVerifier<F>,

    /// `ConstraintId`s of the constraints registered in `qs`.
    ids: MuxConstraintIds,

    /// RVOLE pool for the lifted-VOPE.
    rvole: RV,

    /// Derandomized VOLE pool for multiplication.
    mul_vole: DerandVOLESender<RM, F>,

    /// Queue of pending boolean-check constraints to be verified with `qs`.
    pending_bool_checks: Vec<PendingBoolCheck<F>>,

    /// Fiat-Shamir transcript private to this protocol. Absorbs wire
    /// commitments emitted directly here; embedded sub-protocols own
    /// their own internal transcripts and fold independently.
    transcript: blake3::Hasher,

    /// True iff the boolean-check circuit was registered at
    /// construction.
    boolean_check_enabled: bool,

    /// Lifecycle state.
    state: State,

    _phantom: std::marker::PhantomData<S>,
}

impl<RV, RM, S, F> MuxMulVerifier<RV, RM, S, F>
where
    RV: RVOLESender<F>,
    RM: RVOLESender<F>,
    S: Field,
    F: ExtensionField<S>,
{
    /// Construct a new mux-mul verifier.
    ///
    /// # Arguments
    ///
    /// * `rvole` — random VOLE sender.
    /// * `mul_vole` — derandomized VOLE sender. Must share Δ with `rvole`.
    /// * `boolean_check_enabled` — whether to enforce the `op · op = op`
    ///   booleanness constraint per access.
    pub fn new(rvole: RV, mul_vole: DerandVOLESender<RM, F>, boolean_check_enabled: bool) -> Self {
        let delta = rvole.delta();
        let (_pc, vc, ids) = build_mux_constraints::<F, S>(boolean_check_enabled);
        Self {
            qs: QsVerifier::new(delta, &vc),
            ids,
            rvole,
            mul_vole,
            pending_bool_checks: Vec::new(),
            transcript: blake3::Hasher::new(),
            boolean_check_enabled,
            state: State::Initialized,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Allocates resources. Must be called exactly once.
    ///
    /// # Arguments
    ///
    /// * `num_muls` — number of multiplications.
    pub fn alloc(&mut self, num_muls: usize) -> Result<(), Error> {
        if self.state != State::Initialized {
            return Err(Error::WrongState(self.state));
        }

        self.mul_vole.alloc(num_muls).map_err(Error::DerandVole)?;
        self.rvole
            .alloc(self.vope_vole_count())
            .map_err(|e| Error::Vole(Box::new(e)))?;

        if self.boolean_check_enabled {
            self.pending_bool_checks.reserve(num_muls);
        }
        self.state = State::Allocated;
        Ok(())
    }

    /// Accumulate a batch of multiplications, returning one product
    /// per multiplication.
    ///
    /// # Arguments
    ///
    /// * `ops` — left operands, one per multiplication. Each `ops[i]` must be a
    ///   length-1 wire; the protocol enforces that its cleartext is in `{0,
    ///   1}`.
    /// * `diffs` — right operands, one per multiplication.
    /// * `flush` — a flush message from the prover.
    pub fn accumulate(
        &mut self,
        ops: &[Wire<F>],
        diffs: &[Wire<F>],
        flush: &MuxMulFlush<F>,
    ) -> Result<Vec<Wire<F>>, Error>
    where
        F: Copy + serde::Serialize,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        let m = ops.len();
        if diffs.len() != m || flush.adjustments.len() != m {
            return Err(Error::LengthMismatch);
        }

        let mut prods: Vec<Wire<F>> = Vec::with_capacity(m);

        // Triples to be evaluated with QS.
        let mut triples: Vec<[F; 3]> =
            Vec::with_capacity(diffs.iter().map(|d: &Wire<F>| d.len()).sum());

        for i in 0..m {
            if ops[i].len() != 1 {
                return Err(Error::LengthMismatch);
            }
            let diff = &diffs[i];
            let adj = &flush.adjustments[i];
            let n = diff.len();
            if adj.diffs.len() != n {
                return Err(Error::LengthMismatch);
            }

            // Absorb this adjustment message into the transcript.
            self.transcript
                .update(&bcs::to_bytes(adj).expect("serialize"));

            let prod_keys = self.mul_vole.adjust(adj).map_err(Error::DerandVole)?;

            let op_key = ops[i].key[0];
            for j in 0..n {
                triples.push([op_key, diff.key[j], prod_keys[j]]);
            }

            // Queue the boolean-check.
            if self.boolean_check_enabled {
                self.pending_bool_checks
                    .push(PendingBoolCheck { key: [op_key] });
            }

            prods.push(Wire::new(prod_keys.into()));
        }

        // Bulk QS accumulate for every triple just generated.
        let evaluations: Vec<(mpz_poly_proof_core::ConstraintId, &[F])> = triples
            .iter()
            .map(|t| (self.ids.mul, t.as_slice()))
            .collect();
        self.qs
            .accumulate(&evaluations)
            .map_err(|e| Error::Qs(Box::new(e)))?;

        Ok(prods)
    }

    /// Finalize the protocol.
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`accumulate`](Self::accumulate) before this call —
    /// otherwise the protocol's soundness guarantee no longer holds.
    pub fn finalize(
        mut self,
        transcript: &mut blake3::Hasher,
        proof: &ProofMessage<F>,
    ) -> Result<(), Error>
    where
        F: IntoBytes + FromBytes,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }

        // Lifted-VOPE: pull base VOLEs and rename them as a length-2 VOPE.
        let k = self.vope_vole_count();
        let vole = self
            .rvole
            .try_send_vole(k)
            .map_err(|e| Error::Vole(Box::new(e)))?;
        let vope = verifier_vope_from_vole::<S, F>(&vole);

        // Drain the boolean-check evaluations.
        if let Some(id) = self.ids.bool_check {
            let evaluations: Vec<(mpz_poly_proof_core::ConstraintId, &[F])> = self
                .pending_bool_checks
                .iter()
                .map(|b| (id, b.key.as_slice()))
                .collect();
            self.qs
                .accumulate(&evaluations)
                .map_err(|e| Error::Qs(Box::new(e)))?;
        }

        // Absorb all received messages into the transcript.
        transcript.update(self.transcript.finalize().as_bytes());

        // Draw the qs seed.
        let seed = super::draw_seed(transcript, b"mux-mul::finalize::qs-seed");

        self.qs
            .finalize(proof, &vope, seed)
            .map_err(|e| Error::Qs(Box::new(e)))
    }

    /// Returns VOLEs count needed to build the length-2 lifted-VOPE.
    pub fn vope_vole_count(&self) -> usize {
        <F as ExtensionField<S>>::MONOMIAL_BASIS.len()
    }
}

/// Lifecycle state for the [`MuxMulVerifier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initialized.
    Initialized,
    /// Allocated.
    Allocated,
}

/// Errors produced by [`MuxMulVerifier`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A method was called while the verifier was in the wrong
    /// lifecycle state.
    #[error("mux-mul verifier method called from wrong state: {0:?}")]
    WrongState(State),

    /// A wire's length disagreed with what the verifier expects.
    #[error("bundle length mismatch")]
    LengthMismatch,

    /// Underlying RVOLE error.
    #[error("VOLE error: {0}")]
    Vole(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Derandomized VOLE error.
    #[error("derand VOLE error: {0}")]
    DerandVole(#[source] DerandVOLESenderError),

    /// QuickSilver polynomial-proof error.
    #[error("QS polynomial-proof error: {0}")]
    Qs(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// One pending boolean-check for Quicksilver evaluation.
#[derive(Copy, Clone)]
struct PendingBoolCheck<F> {
    key: [F; 1],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{mux_mul_pair, prover_wire, verifier_wire, vole_adjustment};
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use mpz_vole_core::test::assert_vole;

    /// Assert an `accumulate` call failed with `LengthMismatch`.
    /// `Wire` has no `Debug`, so we can't use `expect_err` here.
    fn assert_mismatch(res: Result<Vec<Wire<Gf2_64>>, Error>, ctx: &str) {
        match res {
            Err(Error::LengthMismatch) => {}
            Err(e) => panic!("{ctx}: expected LengthMismatch, got {e:?}"),
            Ok(_) => panic!("{ctx}: expected LengthMismatch, got Ok"),
        }
    }

    /// `accumulate` rejects every shape disagreement among `ops`,
    /// `diffs`, and the flush's adjustments before touching the VOLE.
    #[test]
    fn accumulate_rejects_length_mismatches() {
        let op = || verifier_wire(vec![Gf2_64::zero()]); // valid length-1 op
        let diff1 = || verifier_wire(vec![Gf2_64::zero()]); // width-1 diff

        // ops vs diffs count mismatch.
        {
            let (_, mut v, _) = mux_mul_pair(1, false);
            let flush = MuxMulFlush {
                adjustments: vec![vole_adjustment(1)],
            };
            assert_mismatch(
                v.accumulate(&[op(), op()], &[diff1()], &flush),
                "ops/diffs count mismatch",
            );
        }

        // adjustment count mismatch (none supplied for one mul).
        {
            let (_, mut v, _) = mux_mul_pair(1, false);
            let flush = MuxMulFlush {
                adjustments: vec![],
            };
            assert_mismatch(
                v.accumulate(&[op()], &[diff1()], &flush),
                "adjustment count mismatch",
            );
        }

        // op wire wider than one slot.
        {
            let (_, mut v, _) = mux_mul_pair(1, false);
            let flush = MuxMulFlush {
                adjustments: vec![vole_adjustment(1)],
            };
            let wide_op = verifier_wire(vec![Gf2_64::zero(), Gf2_64::zero()]);
            assert_mismatch(
                v.accumulate(&[wide_op], &[diff1()], &flush),
                "op must be length-1",
            );
        }

        // adjustment width disagrees with its diff's width.
        {
            let (_, mut v, _) = mux_mul_pair(2, false);
            let diff2 = verifier_wire(vec![Gf2_64::zero(), Gf2_64::zero()]); // width-2 diff
            let flush = MuxMulFlush {
                adjustments: vec![vole_adjustment(1)],
            }; // width-1 adj
            assert_mismatch(
                v.accumulate(&[op()], &[diff2], &flush),
                "adj width must match diff width",
            );
        }
    }

    /// V6: after a single paired `accumulate`, the product wire the
    /// verifier returns (keys) and the one the prover returns
    /// (value + MAC) satisfy the VOLE IT-MAC invariant
    /// `mac = key + Δ · embed(value)` slot-for-slot. This validates the
    /// derandomized multiply end-to-end *without* running the QS proof.
    #[test]
    fn product_wire_satisfies_itmac_invariant() {
        let diff = vec![Gf2(true), Gf2(false), Gf2(true), Gf2(true)];
        let (mut prover, mut verifier, delta) = mux_mul_pair(diff.len(), false);

        // Prover multiplies op = 1 by diff → product = diff.
        let prod_p = prover
            .accumulate(&prover_wire(vec![Gf2(true)]), &prover_wire(diff.clone()))
            .expect("prover accumulate");
        let flush = prover.flush().expect("flush");

        // Verifier op/diff keys are irrelevant to the product wire's own
        // invariant (they only feed the QS mul-gate triples), so any
        // keys of the right widths suffice.
        let v_op = verifier_wire(vec![Gf2_64::zero()]);
        let v_diff = verifier_wire(vec![Gf2_64::zero(); diff.len()]);
        let prods_v = verifier
            .accumulate(&[v_op], &[v_diff], &flush)
            .expect("verifier accumulate");

        assert_eq!(prods_v.len(), 1, "one product wire per multiplication");
        assert_vole(
            delta,
            prods_v[0].key.as_slice(),
            prod_p.value().as_slice(),
            prod_p.mac().as_slice(),
        );
    }

    /// V7: with the booleanness check enabled, `accumulate` queues
    /// exactly one bool-check per multiplication, each bound to that
    /// op's key; with it disabled, none are queued. Asserted by reading
    /// the verifier's private `pending_bool_checks` — no QS finalize.
    #[test]
    fn boolean_check_queues_one_per_op_bound_to_op_key() {
        // Two single-slot multiplications with distinct op keys.
        let k0 = Gf2_64::ONE;
        let k1 = Gf2_64::ONE + Gf2_64::ONE;

        // Enabled: one bool-check per op, bound to the op key.
        {
            let (mut prover, mut verifier, _) = mux_mul_pair(2, true);
            for _ in 0..2 {
                prover
                    .accumulate(&prover_wire(vec![Gf2(true)]), &prover_wire(vec![Gf2(true)]))
                    .expect("prover accumulate");
            }
            let flush = prover.flush().expect("flush");

            let ops = [verifier_wire(vec![k0]), verifier_wire(vec![k1])];
            let diffs = [
                verifier_wire(vec![Gf2_64::zero()]),
                verifier_wire(vec![Gf2_64::zero()]),
            ];
            verifier
                .accumulate(&ops, &diffs, &flush)
                .expect("verifier accumulate");

            assert_eq!(
                verifier.pending_bool_checks.len(),
                2,
                "one bool-check queued per op",
            );
            assert_eq!(verifier.pending_bool_checks[0].key[0], k0);
            assert_eq!(verifier.pending_bool_checks[1].key[0], k1);
        }

        // Disabled: nothing queued.
        {
            let (mut prover, mut verifier, _) = mux_mul_pair(2, false);
            for _ in 0..2 {
                prover
                    .accumulate(&prover_wire(vec![Gf2(true)]), &prover_wire(vec![Gf2(true)]))
                    .expect("prover accumulate");
            }
            let flush = prover.flush().expect("flush");

            let ops = [verifier_wire(vec![k0]), verifier_wire(vec![k1])];
            let diffs = [
                verifier_wire(vec![Gf2_64::zero()]),
                verifier_wire(vec![Gf2_64::zero()]),
            ];
            verifier
                .accumulate(&ops, &diffs, &flush)
                .expect("verifier accumulate");

            assert!(
                verifier.pending_bool_checks.is_empty(),
                "no bool-checks when the flag is off",
            );
        }
    }
}
