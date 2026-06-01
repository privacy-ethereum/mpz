//! RAM protocol — Section 4.3 of the paper.

use mpz_fields::Field;
use mpz_perm_proof_core::Proof as PermProofMsg;
use mpz_vole_core::VoleAdjustment;

use crate::set;

pub use crate::strategy::IntegerLike;
pub use clock::{
    AdditiveClock, AdditiveClockError, Clock, MulClockError, MultiplicativeClock, ProverClock,
    VerifierClock,
};
pub use config::{Config, ConfigBuilder};
pub use mux_mul::{MuxMulFlush, MuxMulProof};
pub use prover::{Error as ProverError, Prover};
pub use strategy::{CommonStrategy, ProverStrategy, VerifierStrategy};
pub use verifier::{Error as VerifierError, Verifier};

pub(crate) mod clock;
pub(crate) mod config;
pub(crate) mod mux_mul;
pub(crate) mod prover;
pub(crate) mod strategy;
pub(crate) mod verifier;

/// One authenticated `(addr, val, clock)` row.
#[derive(Copy, Clone)]
pub(crate) struct Record<W> {
    pub(crate) addr: W,
    pub(crate) val: W,
    pub(crate) clock: W,
}

/// Flush message from the prover.
///
/// May be emitted any number of times during the access phase,
/// letting the verifier process them in parallel with the prover's
/// subsequent work.
pub struct Flush<F>
where
    F: Field,
{
    /// One [`VoleAdjustment`] per [`prover::Prover::access`] call, in call
    /// order.
    ///
    /// Each adjustment derandomizes the `(value, last_access_time)` pair.
    pub access_adj: Vec<VoleAdjustment<F>>,
    /// Mux-mul flush message.
    pub mul_flush: MuxMulFlush<F>,
}

/// Pre-`teardown` message from the prover.
///
/// Front-loads the work that the verifier can begin before the
/// prover starts the tear down.
pub struct TeardownPrepare<F, P>
where
    F: Field,
{
    /// Single adjustment covering the final (value, last_access_time)
    /// state of every memory cell.
    pub teardown_adj: VoleAdjustment<F>,
    /// RAM perm-proof phase-1 preparation message.
    pub preparation: P,
    /// Set pre-teardown message.
    pub set: set::TeardownPrepare<F, P>,
}

/// Teardown message from the prover.
pub struct TeardownMsg<F, BP>
where
    F: Field,
{
    /// RAM perm-proof closing message.
    pub ram_proof: PermProofMsg<F, BP>,
    /// Set perm-proof closing message.
    pub set: set::TeardownMsg<F, BP>,
    /// Mux-mul QS closing proof.
    pub mul_proof: MuxMulProof<F>,
}
