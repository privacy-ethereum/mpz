
use mpz_vm_ir::ValType;
use mpz_memory_core_new::{AuthValueType, AuthValueWidth};
use mpz_vm_core_new::{Error as CoreError, Reg, Trap};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkVmError {
    /// An interpreter or instantiation fault from `mpz-vm-core-new`.
    #[error(transparent)]
    Core(#[from] CoreError),

    /// A runtime trap proven during execution.
    #[error("trap: {0}")]
    Trap(Trap),

    #[error("svole alloc: {0}")]
    SvoleAlloc(String),
    #[error("svole flush: {0}")]
    SvoleFlush(String),
    #[error("svole transfer: {0}")]
    SvoleIo(String),
    #[error("io send: {0}")]
    IoSend(String),
    #[error("io recv: {0}")]
    IoRecv(String),

    #[error("no auth state for reg {reg}")]
    RegAuthMissing { reg: Reg },
    #[error("no auth state for symbolic global {idx}")]
    GlobalAuthMissing { idx: u32 },
    #[error("no authenticated byte in memory at address {addr}")]
    MemAuthMissing { addr: u32 },
    #[error("reg {reg} has type {got:?} but value is {expected:?}")]
    TypeMismatch {
        reg: Reg,
        got: ValType,
        expected: ValType,
    },
    #[error(transparent)]
    AuthValueWidth(#[from] AuthValueWidth),
    #[error(transparent)]
    AuthValueType(#[from] AuthValueType),

    #[error("Fig 5 batch check failed")]
    BatchCheckFailed,
    #[error("flush.input_adjust too short: {got} < {want}")]
    InputAdjustShort { got: usize, want: usize },

    #[error("finalize: no wires for output reg {reg}")]
    OutputWiresMissing { reg: Reg },
    #[error("finalize: output_reg={reg} but no output value")]
    OutputValueMissing { reg: Reg },
    #[error("finalize: output value present but no output reg")]
    OutputRegMissing,
    #[error("verify: prover sent output but verifier has no output reg")]
    UnexpectedOutput,

    #[error("sVOLE delta must have LSB=1 (pointer-bit convention)")]
    DeltaLsb,

    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl ZkVmError {
    /// Returns `true` if this error reflects a feature the zkVM intentionally
    /// does not support (used by the spec harness to skip rather than fail).
    pub fn is_expected_unsupported(&self) -> bool {
        matches!(
            self,
            ZkVmError::Unsupported(_) | ZkVmError::Core(CoreError::Unimplemented(_))
        )
    }
}

pub(crate) type Result<T> = std::result::Result<T, ZkVmError>;

pub(crate) fn unsupported_op(op: &mpz_vm_core_new::Op) -> ZkVmError {
    ZkVmError::Unsupported(format!("zk-vm: op not yet supported: {op:?}"))
}

pub(crate) fn unsupported_binary<T>(op: mpz_vm_ir::BinaryOp) -> Result<T> {
    Err(ZkVmError::Unsupported(format!(
        "zk-vm: binary op not yet supported: {op:?}"
    )))
}

pub(crate) fn unsupported_unary<T>(op: mpz_vm_ir::UnaryOp) -> Result<T> {
    Err(ZkVmError::Unsupported(format!(
        "zk-vm: unary op not yet supported: {op:?}"
    )))
}
