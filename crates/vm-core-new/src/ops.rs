//! Symbolic operations for the backend.

use crate::Trace;

/// A single symbolic operation for the backend.
#[derive(Debug, Clone)]
pub enum SymbolicOp {
    /// Execute a trace of instructions.
    Trace(Trace),
    /// Call a host function.
    HostFn(HostFnId),
    /// Signal that function execution is complete.
    FnComplete,
}

/// Host function identifiers.
#[derive(Debug, Clone, Copy)]
pub enum HostFnId {
    /// Decode the top of stack i32 value.
    DecodeI32(usize),
    /// Decode the top of stack i64 value.
    DecodeI64(usize),
    /// Decode the top of stack f32 value.
    DecodeF32(usize),
    /// Decode the top of stack f64 value.
    DecodeF64(usize),
}

/// Bundle of symbolic operations for the backend.
#[derive(Debug, Clone, Default)]
pub struct SymbolicOps {
    ops: Vec<SymbolicOp>,
}

impl SymbolicOps {
    /// Creates a new empty bundle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes an operation to the bundle.
    pub fn push(&mut self, op: SymbolicOp) {
        self.ops.push(op);
    }

    /// Returns the operations in the bundle.
    pub fn ops(&self) -> &[SymbolicOp] {
        &self.ops
    }

    /// Returns true if the bundle is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}
