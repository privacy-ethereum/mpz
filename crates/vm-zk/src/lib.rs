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
pub(crate) mod cost;
pub(crate) mod error;
pub(crate) mod finalize;
pub(crate) mod host;
mod prover;
pub(crate) mod replay;
pub(crate) mod reveal;
mod verifier;

use host::RevealPayload;

pub use error::ZkVmError;
pub use prover::Prover;
pub use verifier::Verifier;

pub(crate) const VOPE_BITS: usize = 128;

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
