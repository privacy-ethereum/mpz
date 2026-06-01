//! Prover side of the mux-multiplication protocol.

use mpz_common::future::Output;
use mpz_fields::Field;
use mpz_poly_proof_core::{ExtensionField, prover::Prover as QsProver};
use mpz_vole_core::{
    DerandVOLEReceiver, DerandVOLEReceiverError, RVOLEReceiver, VOLEReceiver, VoleAdjustment,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::wire::ProverWire as Wire;

use super::{
    MuxConstraintIds, MuxMulFlush, MuxMulProof, build_mux_constraints,
    vope_from_vole::prover_vope_from_vole,
};

/// Mux-multiplication prover.
pub struct MuxMulProver<RV, RD, S, F>
where
    RV: RVOLEReceiver<S, F>,
    RD: RVOLEReceiver<S, F>,
    S: Field,
    F: ExtensionField<S>,
{
    /// QuickSilver polynomial protocol prover. MACs live in `F`,
    /// values in the subfield `S`.
    qs: QsProver<F, S>,

    /// `ConstraintId`s of the constraints registered in `qs`.
    ids: MuxConstraintIds,

    /// RVOLE pool for the lifted-VOPE.
    rvole: RV,

    /// Derandomized VOLE pool for multiplication.
    mul_vole: DerandVOLEReceiver<RD, S, F>,

    /// Queue of pending multiplication to be proven with `qs`.
    pending_mults: Vec<PendingMult<S, F>>,

    /// Queue of pending boolean-check constraints to be proven with `qs`.
    pending_bool_checks: Vec<PendingBoolCheck<S, F>>,

    /// Outbound queue of VOLE adjustments.
    pending_adjustments: Vec<VoleAdjustment<F>>,

    /// Fiat-Shamir transcript private to this protocol. Absorbs wire
    /// commitments emitted directly here; embedded sub-protocols own
    /// their own internal transcripts and fold independently.
    transcript: blake3::Hasher,

    /// True iff the boolean-check circuit was registered at
    /// construction.
    boolean_check_enabled: bool,

    /// Lifecycle state.
    state: State,
}

impl<RV, RD, S, F> MuxMulProver<RV, RD, S, F>
where
    RV: RVOLEReceiver<S, F>,
    RD: RVOLEReceiver<S, F>,
    S: Field,
    F: ExtensionField<S>,
{
    /// Construct a new mux-mul prover.
    ///
    /// # Arguments
    ///
    /// * `rvole` — random VOLE receiver.
    /// * `mul_vole` — derandomized VOLE receiver.
    /// * `boolean_check_enabled` — whether to enforce the `op · op = op`
    ///   booleanness constraint per access.
    pub fn new(
        rvole: RV,
        mul_vole: DerandVOLEReceiver<RD, S, F>,
        boolean_check_enabled: bool,
    ) -> Self {
        let (pc, _vc, ids) = build_mux_constraints::<F, S>(boolean_check_enabled);
        Self {
            qs: QsProver::new(&pc),
            ids,
            rvole,
            mul_vole,
            pending_mults: Vec::new(),
            pending_bool_checks: Vec::new(),
            pending_adjustments: Vec::new(),
            transcript: blake3::Hasher::new(),
            boolean_check_enabled,
            state: State::Initialized,
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

        self.pending_mults.reserve_exact(num_muls);
        self.pending_adjustments.reserve(num_muls);
        if self.boolean_check_enabled {
            self.pending_bool_checks.reserve(num_muls);
        }
        self.state = State::Allocated;
        Ok(())
    }

    /// Accumulate one multiplication, returning the product wire.
    ///
    /// # Arguments
    ///
    /// * `op` — left operand. Must be `{0, 1}`; the protocol enforces this.
    /// * `diff` — right operand.
    pub fn accumulate(&mut self, op: &Wire<S, F>, diff: &Wire<S, F>) -> Result<Wire<S, F>, Error>
    where
        S: Field,
        F: Copy,
        F: serde::Serialize,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if op.len() != 1 {
            return Err(Error::LengthMismatch);
        }
        let n = diff.len();

        // Cleartext per-slot product.
        let prod_value: Vec<S> = (0..n).map(|i| op.value()[0] * diff.value()[i]).collect();

        // Derandomize the product.
        let mut prod_fut = self
            .mul_vole
            .queue_recv_vole(&prod_value)
            .map_err(Error::DerandVole)?;
        let adjustment = self.mul_vole.adjust().map_err(Error::DerandVole)?;
        let prod_macs: Vec<F> = prod_fut
            .try_recv()
            .map_err(|_| Error::VoleFutureUnresolved)?
            .ok_or(Error::VoleFutureUnresolved)?
            .macs;

        // Queue for proving.
        for i in 0..n {
            self.pending_mults.push(PendingMult {
                values: [op.value()[0], diff.value()[i], prod_value[i]],
                macs: [op.mac()[0], diff.mac()[i], prod_macs[i]],
            });
        }
        if self.boolean_check_enabled {
            self.pending_bool_checks.push(PendingBoolCheck {
                value: [op.value()[0]],
                mac: [op.mac()[0]],
            });
        }

        // Absorb into transcript.
        self.transcript
            .update(&bcs::to_bytes(&adjustment).expect("serialize"));
        self.pending_adjustments.push(adjustment);

        Ok(Wire::new(prod_value.into(), prod_macs.into()))
    }

    /// Emits a flush message.
    pub fn flush(&mut self) -> Result<MuxMulFlush<F>, Error> {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        Ok(MuxMulFlush {
            adjustments: std::mem::take(&mut self.pending_adjustments),
        })
    }

    /// Finalize the protocol, returning the proof.
    ///
    /// The caller is responsible for calling [`flush`](Self::flush)
    /// before invoking this method.
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`accumulate`](Self::accumulate) before this call —
    /// otherwise the protocol's soundness guarantee no longer holds.
    pub fn finalize(mut self, transcript: &mut blake3::Hasher) -> Result<MuxMulProof<F>, Error>
    where
        F: IntoBytes + FromBytes,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if !self.pending_adjustments.is_empty() {
            return Err(Error::UnflushedAdjustments {
                pending: self.pending_adjustments.len(),
            });
        }

        // Lifted-VOPE: pull base VOLEs and rename them as a length-2 VOPE.
        let k = self.vope_vole_count();
        let vole = self
            .rvole
            .try_recv_vole(k)
            .map_err(|e| Error::Vole(Box::new(e)))?;
        let vope = prover_vope_from_vole::<S, F>(&vole);

        // Absorb all emitted messages into the transcript.
        transcript.update(self.transcript.finalize().as_bytes());

        // Draw the qs seed.
        let seed = super::draw_seed(transcript, b"mux-mul::finalize::qs-seed");

        // Prepare qs evaluations and finalize qs proof.
        let bool_id = self.ids.bool_check;
        let mut evaluations: Vec<(mpz_poly_proof_core::ConstraintId, &[F], &[S])> =
            Vec::with_capacity(self.pending_mults.len() + self.pending_bool_checks.len());
        for m in &self.pending_mults {
            evaluations.push((self.ids.mul, m.macs.as_slice(), m.values.as_slice()));
        }
        if let Some(id) = bool_id {
            for b in &self.pending_bool_checks {
                evaluations.push((id, b.mac.as_slice(), b.value.as_slice()));
            }
        }

        self.qs
            .accumulate(&evaluations, seed)
            .map_err(|e| Error::Qs(Box::new(e)))?;

        let qs_proof = self
            .qs
            .finalize(&vope)
            .map_err(|e| Error::Qs(Box::new(e)))?;

        Ok(MuxMulProof { qs_proof })
    }

    /// Returns VOLEs count needed to build the length-2 lifted-VOPE.
    fn vope_vole_count(&self) -> usize {
        <F as ExtensionField<S>>::MONOMIAL_BASIS.len()
    }
}

/// Lifecycle state for the [`MuxMulProver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initialized.
    Initialized,
    /// Allocated.
    Allocated,
}

/// One pending multiplication for Quicksilver evaluation.
#[derive(Copy, Clone)]
struct PendingMult<S, F> {
    values: [S; 3],
    macs: [F; 3],
}

/// One pending boolean-check for Quicksilver evaluation.
#[derive(Copy, Clone)]
struct PendingBoolCheck<S, F> {
    value: [S; 1],
    mac: [F; 1],
}

/// Errors produced by [`MuxMulProver`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A method was called while the prover was in the wrong state.
    #[error("mux-mul prover method called from wrong state: {0:?}")]
    WrongState(State),

    /// A wire's length disagreed with what was expected.
    #[error("bundle length mismatch")]
    LengthMismatch,

    /// Underlying RVOLE error.
    #[error("VOLE error: {0}")]
    Vole(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Derandomized VOLE error.
    #[error("derand VOLE error: {0}")]
    DerandVole(#[source] DerandVOLEReceiverError),

    /// VOLE future failed to resolve.
    #[error("VOLE future failed to resolve after adjust")]
    VoleFutureUnresolved,

    /// finalize was called while adjustments were still pending.
    #[error("finalize called with {pending} unflushed adjustments")]
    UnflushedAdjustments {
        /// Number of adjustments still queued.
        pending: usize,
    },

    /// QuickSilver polynomial-proof error.
    #[error("QS polynomial-proof error: {0}")]
    Qs(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{mux_mul_pair, prover_wire};
    use mpz_fields::gf2::Gf2;

    /// `accumulate` returns the elementwise product `op · diff` in the
    /// product wire's cleartext: `prod[i] = op[0] · diff[i]`.
    #[test]
    fn accumulate_product_is_op_times_diff_elementwise() {
        let diff = vec![Gf2(true), Gf2(false), Gf2(true), Gf2(true)];

        // op = 1 → product equals diff.
        {
            let (mut prover, _, _) = mux_mul_pair(diff.len(), false);
            let prod = prover
                .accumulate(&prover_wire(vec![Gf2(true)]), &prover_wire(diff.clone()))
                .expect("accumulate");
            assert_eq!(prod.value().as_slice(), diff.as_slice());
        }

        // op = 0 → product is all-zero, regardless of diff.
        {
            let (mut prover, _, _) = mux_mul_pair(diff.len(), false);
            let prod = prover
                .accumulate(&prover_wire(vec![Gf2(false)]), &prover_wire(diff.clone()))
                .expect("accumulate");
            assert!(
                prod.value().iter().all(|&v| v == Gf2::zero()),
                "op = 0 must zero every product slot",
            );
        }
    }
}
