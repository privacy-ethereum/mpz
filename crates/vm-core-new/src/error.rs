use ir::ValType;

use crate::value::ValueError;

/// WebAssembly trap reasons - these arise from normal WASM semantics.
///
/// Traps are abnormal termination conditions defined by the WebAssembly spec.
/// They occur during valid program execution when certain runtime conditions
/// are violated.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Trap {
    #[error("unreachable instruction executed")]
    Unreachable,

    #[error("integer divide by zero")]
    DivideByZero,

    #[error("integer overflow")]
    IntegerOverflow,

    #[error("out of bounds memory access")]
    MemoryOutOfBounds,

    #[error("undefined element")]
    UndefinedElement,

    #[error("indirect call type mismatch")]
    IndirectCallTypeMismatch,

    #[error("call stack exhausted")]
    CallStackExhausted,

    #[error("process exit with code {0}")]
    Exit(i32),
}

/// Errors that can occur during VM execution.
#[derive(thiserror::Error, Debug)]
pub enum VmError {
    /// WebAssembly trap - a runtime error defined by the WASM spec.
    #[error("trap: {0}")]
    Trap(Trap),

    /// Value conversion error.
    #[error(transparent)]
    Value(#[from] ValueError),

    /// Feature not supported by this VM implementation.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// Internal VM error - indicates a bug or unexpected state.
    #[error("internal error: {0}")]
    Internal(String),

    // === Validation/setup errors (not traps) ===
    #[error("stack underflow")]
    StackUnderflow,

    #[error("type mismatch: expected {expected:?}, got {got:?}")]
    TypeMismatch { expected: ValType, got: ValType },

    #[error("attempted an unsupported operation on a symbolic value")]
    SymbolicOperation,

    #[error("attempted to return a symbolic value")]
    SymbolicReturn,

    #[error("attempted to access memory with a symbolic value")]
    SymbolicAddress,

    #[error("expected a concrete value but it was symbolic")]
    SymbolicValue,

    #[error("undefined function: {0}")]
    UndefinedFunction(u32),

    #[error("attempted to call a function which is not exported")]
    InvalidFunction(u32),

    #[error("undefined local: {0}")]
    UndefinedLocal(u32),

    #[error("undefined global: {0}")]
    UndefinedGlobal(u32),

    #[error("memory not defined")]
    MemoryNotDefined,

    #[error("unsupported import: {module}::{name}")]
    UnsupportedImport { module: String, name: String },

    #[error("import signature mismatch: {name}")]
    ImportSignatureMismatch { name: String },

    /// Attempted to branch on a symbolic value (if, br_if, br_table, select).
    #[error("cannot branch on symbolic value")]
    SymbolicConditional,

    /// Execution blocked, requires backend flush.
    #[error("execution blocked, requires backend flush")]
    Blocked,

    /// I/O error during communication with peer.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<Trap> for VmError {
    fn from(trap: Trap) -> Self {
        VmError::Trap(trap)
    }
}

impl VmError {
    /// Returns `true` if this error arises from an unsupported feature.
    pub fn is_unsupported(&self) -> bool {
        matches!(self, VmError::Unsupported(_))
    }

    /// Returns `true` if this error is due to branching on a symbolic value.
    pub fn is_symbolic_conditional(&self) -> bool {
        matches!(self, VmError::SymbolicConditional)
    }

    /// Returns `true` if this error is due to an operation requiring concrete
    /// value.
    pub fn is_symbolic_value(&self) -> bool {
        matches!(self, VmError::SymbolicValue | VmError::SymbolicReturn)
    }

    /// Returns `true` if this error is due to a symbolic address.
    pub fn is_symbolic_address(&self) -> bool {
        matches!(self, VmError::SymbolicAddress)
    }
}
