pub mod arithmetic;
pub(crate) mod bitset;
mod call;
mod error;
pub mod ideal;
mod imports;
mod memory;
mod state;
pub mod thread;
pub mod value;

pub use call::{Call, Param};
pub use error::{Trap, VmError};
pub use ir::{BlockId, Module, Reg, ValType};
pub use memory::Memory;
pub use state::Global;
pub use thread::{Context, Frame, StepResult, Thread};
pub use value::ValueError;

use ir;
use value::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Public,
    Blind,
}

/// A memory I/O write declaration passed to [`Vm::write`].
#[derive(Debug, Clone, Copy)]
pub enum Write<'a> {
    /// Our bytes. Copied into linear memory immediately; sent to peer
    /// on the next flush. The range becomes tainted on both sides.
    Private(&'a [u8]),
    /// Peer's bytes. Linear memory is left untouched until flush, at
    /// which point `len` bytes are received from the peer and written
    /// to `ptr`. The range becomes tainted on both sides.
    Blind(usize),
    /// Agreed-upon bytes. Copied into linear memory immediately; no
    /// I/O is performed. The range is untainted after flush.
    Public(&'a [u8]),
}

/// Core VM interface — queue memory I/O operations and execute
/// functions against a module.
pub trait Vm {
    /// Queue a memory I/O write at `ptr`. The bytes (for `Private` /
    /// `Public`) are copied into linear memory immediately and the
    /// range is recorded in the pending diff; the actual I/O with
    /// the peer happens on the next flush. Later `write` / `reveal`
    /// calls override earlier ones on any overlapping bytes.
    fn write(&mut self, ptr: u32, w: Write<'_>) -> Result<(), VmError>;

    /// Queue a reveal of `ptr..ptr+len`. On flush the tainted bytes
    /// are exchanged with the peer and the range becomes public.
    fn reveal(&mut self, ptr: u32, len: usize) -> Result<(), VmError>;

    /// Read raw bytes from linear memory. Errors if any byte of the
    /// requested region is tainted or in a pending blind region.
    fn read(&self, ptr: u32, len: usize) -> Result<&[u8], VmError>;

    /// Call an exported function, flushing any pending I/O first.
    fn call(
        &mut self,
        io: &mut mpz_common::Context,
        func_idx: u32,
        params: Vec<Param>,
    ) -> impl std::future::Future<Output = Result<Option<Value>, VmError>>;
}

/// An operand that is either symbolic or concrete.
#[derive(Debug, Clone, Copy)]
pub enum Operand {
    Concrete(Value),
    Symbol(Reg),
}

/// A symbolic operation with concrete operand values embedded.
#[derive(Debug, Clone)]
pub enum Op {
    Copy {
        dst: Reg,
        src: Reg,
    },
    GlobalGet {
        dst: Reg,
        global_idx: u32,
    },
    GlobalSet {
        global_idx: u32,
        src: Operand,
    },
    Select {
        dst: Reg,
        cond: Operand,
        if_true: Operand,
        if_false: Operand,
    },
    Unary {
        dst: Reg,
        op: ir::UnaryOp,
        src: Reg,
    },
    Binary {
        dst: Reg,
        op: ir::BinaryOp,
        lhs: Operand,
        rhs: Operand,
    },
    // Loads (symbolic address)
    I32Load {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I64Load {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    F32Load {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    F64Load {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I32Load8S {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I32Load8U {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I32Load16S {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I32Load16U {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I64Load8S {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I64Load8U {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I64Load16S {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I64Load16U {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I64Load32S {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    I64Load32U {
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
    },
    // Stores (symbolic address or value)
    I32Store {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
    I64Store {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
    F32Store {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
    F64Store {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
    I32Store8 {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
    I32Store16 {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
    I64Store8 {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
    I64Store16 {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
    I64Store32 {
        addr: Operand,
        val: Operand,
        memarg: ir::MemArg,
    },
}

/// A directive yielded by Thread::step().
#[derive(Debug, Clone)]
pub enum Directive {
    Call {
        dst: Option<Reg>,
        func_idx: u32,
        args: Vec<Operand>,
    },
    Return {
        return_reg: Option<Reg>,
    },
    Op(Op),
    Branch {
        func_idx: u32,
        block: BlockId,
        cond: Option<Operand>,
        exit: Option<BlockId>,
        bail_out: bool,
    },
    Complete,
}
