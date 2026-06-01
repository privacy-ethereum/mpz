//! Set with membership queries — Section 4.2 of the paper.

use mpz_fields::Field;
use mpz_perm_proof_core::Proof;
use mpz_vole_core::VoleAdjustment;

pub(crate) mod prover;
pub(crate) mod verifier;

pub use prover::{Error as ProverError, Prover};
pub use verifier::{Error as VerifierError, Verifier};

/// Pre-`teardown` message from the prover.
///
/// Bundles the verifier-side teardown work that can run in parallel
/// with the prover building the closing [`TeardownMsg`].
pub struct TeardownPrepare<F, P>
where
    F: Field,
{
    /// All VOLE adjustments accumulated during `lookup` plus the
    /// single teardown adjustment, in order.
    pub adjustments: Vec<VoleAdjustment<F>>,
    /// Perm-proof phase-1 preparation DTO — see
    /// [`Backend::Preparation`](mpz_perm_proof_core::backend::Backend::Preparation).
    pub preparation: P,
}

/// Closing message from [`Prover::teardown`].
pub struct TeardownMsg<F, BP>
where
    F: Field,
{
    /// Perm-proof closing message.
    pub proof: Proof<F, BP>,
}

/// One authenticated `(key, version)` record.
#[derive(Copy, Clone)]
pub(crate) struct Record<W> {
    pub(crate) key: W,
    pub(crate) version: W,
}
