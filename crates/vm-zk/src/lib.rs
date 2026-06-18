//! A zero-knowledge virtual machine for proving execution of `mpz-vm-ir`
//! modules.
//!
//! This crate provides the two parties of a designated-verifier
//! zero-knowledge proof of program execution. A program is expressed as an
//! `mpz-vm-ir` [`Module`](mpz_vm_ir::Module) and run through the
//! [`Vm`](mpz_vm_core::Vm) interface implemented by both parties.
//!
//! The [`Prover`] holds the private witness and produces a proof that the
//! module was executed correctly, while the [`Verifier`] checks that proof
//! against the public inputs and outputs without learning the witness. The two
//! parties communicate over a shared channel and are driven through the same
//! [`Vm`](mpz_vm_core::Vm) trait, so the same program description executes
//! on both sides.

use std::collections::BTreeMap;

use mpz_vm_core::{Trap, value::Value};
use mpz_zk_core::Proof;

pub(crate) mod capture;
pub(crate) mod commit;
pub(crate) mod config;
pub(crate) mod cost;
pub(crate) mod error;
pub(crate) mod finalize;
pub(crate) mod host;
pub(crate) mod memlog;
mod prover;
pub(crate) mod replay;
pub(crate) mod reveal;
pub(crate) mod segment;
mod verifier;

use host::RevealPayload;

pub use config::{Config, ConfigBuilder};
pub use error::ZkVmError;
pub use prover::Prover;
pub use verifier::Verifier;

pub(crate) const VOPE_BITS: usize = 128;

/// Default per-chunk op-cost cap, sized to sit within the net correlations one
/// Ferret extension can deliver. A single round of the largest regular-LPN
/// params ([`mpz_ot_core::ferret::REGULAR_PARAMS`]) yields `n` correlations but
/// must reserve `t·log2(n/t) + k + CSP` of them as seed for the next iteration,
/// so the usable yield is `n - iteration_cost = 15_015_684`. Capping below that
/// keeps a chunk's sVOLE demand serviceable by one extension round, with margin
/// left for the per-chunk commit and VOPE overhead.
pub const DEFAULT_CHUNK_CAP: usize = 15_000_000;

/// Number of proving segments a full chunk is split into when the per-segment
/// cost is auto-derived (the default).
///
/// Segments are committed and folded by independent rayon workers, so the
/// count sets the available intra-chunk parallelism. Chosen to comfortably
/// oversubscribe a typical core count (≈4× a 16-core host) for good
/// work-stealing balance, while staying small enough that the per-segment
/// boundary overhead — each worker re-seeds from every prior boundary, an
/// O(segments²) cost — stays well below the linear replay work. The actual
/// segment count scales down for chunks smaller than the cap, since the target
/// is derived from the shared [`DEFAULT_CHUNK_CAP`].
pub(crate) const TARGET_SEGMENTS: usize = 64;

/// Floor on the auto-derived per-segment gate-bit cost, so a small
/// [`chunk_cap`](ConfigBuilder::chunk_cap) never produces segments too tiny to
/// amortize their boundary commitment ("a segment for every gate").
pub(crate) const MIN_SEGMENT_COST: usize = 50_000;

/// Resolves the effective per-segment gate-bit target both parties use to
/// place segment marks.
///
/// `Some(cost)` is honored verbatim — an explicit
/// [`segment_cost`](ConfigBuilder::segment_cost) override. `None`
/// auto-derives a target from the shared `chunk_cap` so a full chunk splits
/// into about [`TARGET_SEGMENTS`] segments: workload-proportional, and
/// identical on both sides because it depends only on protocol-shared values,
/// never on local core count (which may differ between prover and verifier).
/// An unbounded chunk (`chunk_cap = None`) has no basis to divide and proves
/// as a single segment.
pub(crate) fn effective_segment_cost(
    segment_cost: Option<usize>,
    chunk_cap: Option<usize>,
) -> Option<usize> {
    match segment_cost {
        Some(cost) => Some(cost),
        None => chunk_cap.map(|cap| (cap / TARGET_SEGMENTS).max(MIN_SEGMENT_COST)),
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ProofMessage {
    pub(crate) output: Option<Value>,
    pub(crate) revealed: Vec<u8>,
    pub(crate) proof: Proof,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ChunkOutcome {
    pub(crate) trap_at: Option<u64>,
    pub(crate) trap: Option<Trap>,
    /// Payloads disclosed by reveals in this chunk, keyed by reveal id. The
    /// verifier merges these before capturing so it can resolve the reveals in
    /// lockstep; replay then opens each against its committed wires.
    pub(crate) revealed: BTreeMap<u32, RevealPayload>,
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_CHUNK_CAP;

    /// `DEFAULT_CHUNK_CAP` must stay within the net correlations one Ferret
    /// extension delivers — its output `n` less the `t·log2(n/t) + k + CSP`
    /// seed it reserves for the next iteration — so a chunk's sVOLE demand fits
    /// a single extension round. Guards against a future params change that
    /// would shrink the net yield below the cap.
    #[test]
    fn default_chunk_cap_fits_ferret_iteration() {
        // Ferret's computational security parameter (`config::CSP`), inlined
        // since it is private to `mpz_ot_core`.
        const CSP: usize = 128;
        let net = mpz_ot_core::ferret::REGULAR_PARAMS
            .iter()
            .map(|p| {
                let iteration_cost = p.t * (p.n / p.t).ilog2() as usize + p.k + CSP;
                p.n - iteration_cost
            })
            .max()
            .expect("Ferret defines at least one LPN parameter set");
        assert!(
            DEFAULT_CHUNK_CAP <= net,
            "DEFAULT_CHUNK_CAP {DEFAULT_CHUNK_CAP} exceeds Ferret net yield {net}"
        );
    }
}
