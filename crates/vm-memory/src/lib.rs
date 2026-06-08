//! IT-MAC authenticated wire-layer state and storage primitives.
//!
//! This crate houses the building blocks shared by the new
//! prover/verifier pipeline:
//!
//! - [`Bit`], [`Byte`], [`AuthValue`] — generic-over-`W` containers: per-bit
//!   authentication, byte-shaped bit bundles, and typed register values
//!   mirroring `mpz_vm_core::Value`.
//! - [`Registers<T>`] — sparse register file keyed by absolute `Reg`. Generic
//!   over the cell type for testability.
//! - [`LinearMemory<W>`] — sparse byte-addressed memory keyed by `u32`,
//!   storing one [`Byte<W>`] per address plus the public-0/1 wires. Exposes
//!   typed accessors implementing the WASM load/store instruction set for the
//!   family of instructions that are pure wire routing (concat, slice,
//!   zero-extend, sign-extend).

mod auth;
mod memory;
mod registers;
mod state;

pub use auth::{
    AuthValue, AuthValueType, AuthValueWidth, Bit, Byte, F32, F64, I32, I64, Wire,
};
pub use memory::LinearMemory;
pub use mpz_vm_ir::ValType;
pub use registers::Registers;
pub use state::AuthState;
