//! Composed IT-MAC state: per-register and per-global [`AuthValue`]s
//! plus per-byte [`Byte`]s for linear memory.
//!
//! [`AuthState`] is just the union of [`Registers<AuthValue>`] (used
//! for both the register file and the symbolic globals table) and
//! [`LinearMemory<Byte>`]. Frame layout is the caller's concern; this
//! type is a typed bag of authenticated values.

use crate::{
    auth::{AuthValue, Bit},
    memory::LinearMemory,
    registers::Registers,
};

/// Authenticated state for every symbolic register, symbolic global,
/// and tainted memory byte in the current run.
///
/// `regs` is frame-scoped; `globals` and `memory` are long-lived
/// (shared across calls), mirroring WASM's global and linear-memory
/// semantics.
#[derive(Debug)]
pub struct AuthState {
    pub regs: Registers<AuthValue>,
    pub globals: Registers<AuthValue>,
    pub memory: LinearMemory,
}

impl AuthState {
    /// Create empty state whose memory uses `zero`/`one` as its public-0
    /// and public-1 wires.
    pub fn new(zero: Bit, one: Bit) -> Self {
        Self {
            regs: Registers::default(),
            globals: Registers::default(),
            memory: LinearMemory::new(zero, one),
        }
    }
}
