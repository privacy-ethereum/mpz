//! Core abstractions for executing [`mpz_vm_ir`] modules under a multi-party
//! virtual machine.
//!
//! The crate splits execution into a deterministic, party-agnostic
//! [`Thread`] interpreter and an embedder that drives it. A thread steps
//! through an [`mpz_vm_ir`] [`Module`], emitting a stream of [`Directive`]s that
//! describe the abstract operations to perform. Operations whose operands are
//! [`Visibility::Private`] or [`Visibility::Blind`] are expressed
//! symbolically through [`Operand`] and [`Op`]; operations on
//! [`Visibility::Public`] data are evaluated concretely in-thread.
//!
//! The [`Vm`] trait is the high-level interface an embedder exposes for
//! writing inputs, revealing outputs, reading memory, and invoking functions.
//! The `mpz-vm-ideal` crate provides a single-machine reference implementation
//! of [`Vm`] used for testing.
//!
//! # Threading model
//!
//! - [`Thread`] holds the per-party interpreter state and produces a
//!   [`StepResult`] on each [`Thread::step`], which is passed the shared
//!   [`Module`] and mutable [`Global`] state.
//! - When a thread cannot proceed without external input it returns
//!   [`StepResult::Blocked`] carrying a [`Pending`] request, which the
//!   embedder satisfies with the matching `Thread::resolve_*` method.

pub(crate) mod analysis;
pub(crate) mod arithmetic;
pub(crate) mod bitset;
mod call;
mod error;
mod memory;
mod state;
pub(crate) mod taint;
pub mod thread;
pub mod trap;
pub mod value;

pub use call::{Call, Param};
pub use error::Error;
pub use memory::Memory;
pub use mpz_vm_ir::{Module, Reg, ValType};
pub use trap::{MaybeTrap, Trap};

use mpz_vm_ir::BlockId;
pub use state::Global;
pub use thread::{Frame, Pending, StepResult, Thread};
pub use value::ValueError;

use value::Value;

/// The visibility class of a value in the virtual machine.
///
/// Visibility determines whether a value is evaluated concretely or carried
/// symbolically, and which party (if any) holds its bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// A value held privately by the local party.
    Private,
    /// A value known to all parties and evaluated concretely.
    Public,
    /// A value held by another party and not by the local party.
    Blind,
}

/// An input to write into virtual machine memory.
///
/// Each variant selects both the [`Visibility`] of the written bytes and how
/// the data is supplied.
#[derive(Debug, Clone, Copy)]
pub enum Write<'a> {
    /// Private bytes contributed by the local party.
    Private(&'a [u8]),
    /// A blind region of the given length, contributed by another party.
    Blind(usize),
    /// Public bytes known to all parties.
    Public(&'a [u8]),
}

/// A virtual machine that can ingest inputs, run functions, and reveal
/// outputs.
///
/// Implementors drive an underlying [`Thread`] and mediate access to its
/// [`Memory`], translating the abstract [`Directive`] stream into concrete
/// effects for a particular execution backend.
pub trait Vm {
    /// The error type this VM reports. Each backend defines its own, expressing
    /// the conditions it can actually encounter (interpreter faults, traps, I/O,
    /// and whatever it deems unsupported) without funnelling through a shared
    /// umbrella.
    type Error: core::error::Error;

    /// Writes `w` into memory at byte offset `ptr`.
    ///
    /// The [`Write`] variant determines the [`Visibility`] applied to the
    /// written region.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the write cannot be performed, for example
    /// when the target range is out of bounds or memory is not defined.
    fn write(&mut self, ptr: u32, w: Write<'_>) -> Result<(), Self::Error>;

    /// Reveals `len` bytes of memory starting at byte offset `ptr`, making
    /// them public to all parties.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the range cannot be revealed, for example
    /// when it is out of bounds or memory is not defined.
    fn reveal(&mut self, ptr: u32, len: usize) -> Result<(), Self::Error>;

    /// Returns `len` bytes of memory starting at byte offset `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the range cannot be read, for example when it
    /// is out of bounds or memory is not defined.
    fn read(&self, ptr: u32, len: usize) -> Result<&[u8], Self::Error>;

    /// Invokes the function at `func_idx` with `params`, returning its result
    /// value if any.
    ///
    /// The `io` context carries the communication channels used to coordinate
    /// with other parties for the duration of the call.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the call fails, for example when `func_idx`
    /// refers to no function or an unsupported operation is encountered.
    fn call(
        &mut self,
        io: &mut mpz_common::Context,
        func_idx: u32,
        params: Vec<Param>,
    ) -> impl std::future::Future<Output = Result<Option<Value>, Self::Error>>;

    /// Flushes any queued memory operations, committing them over `io` without
    /// running a function.
    ///
    /// [`write`](Self::write) and [`reveal`](Self::reveal) stage their effects
    /// for the next exchange, which normally happens at the start of the next
    /// [`call`](Self::call). `commit` performs that exchange on demand: queued
    /// inputs are committed and queued reveals are opened up front. With nothing
    /// left pending, a subsequent [`call_local`](Self::call_local) can run with
    /// no further communication.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the exchange over `io` fails.
    fn commit(
        &mut self,
        io: &mut mpz_common::Context,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>>;

    /// Invokes the function at `func_idx` with `params` using only local work,
    /// without an `io` context.
    ///
    /// Unlike [`call`](Self::call), this performs no communication with other
    /// parties: it runs the function only while every step can be evaluated from
    /// values this party already holds. It is intended for functions whose
    /// inputs are all public (or have already been committed via
    /// [`commit`](Self::commit)).
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the call would require communication — for
    /// example when private or blind inputs remain uncommitted, when a reveal is
    /// pending, or when execution reaches a symbolic operation that cannot be
    /// resolved locally — in addition to the usual failures: an invalid
    /// `func_idx`, a signature mismatch, or a trap.
    fn call_local(
        &mut self,
        func_idx: u32,
        params: Vec<Param>,
    ) -> Result<Option<Value>, Self::Error>;
}

/// An operand of an [`Op`], either a concrete value or a symbolic register.
///
/// Concrete operands carry a fully known [`Value`]. Symbolic operands name
/// the [`Reg`] holding the value and additionally carry its [`Value`] when it
/// is available to the local party.
#[derive(Debug, Clone, Copy)]
pub enum Operand {
    /// A value known concretely to all parties.
    Concrete(Value),
    /// A value held in a register `reg`.
    ///
    /// `value` is `Some` iff the value is available to the local party.
    Symbol {
        /// The absolute register holding the value.
        reg: Reg,
        /// The concrete value, present iff available to the local party.
        value: Option<Value>,
    },
}

impl Operand {
    /// Returns `true` if the operand is concrete.
    pub fn is_concrete(&self) -> bool {
        matches!(self, Operand::Concrete(_))
    }

    /// Returns `true` if the operand is a symbol.
    pub fn is_symbol(&self) -> bool {
        matches!(self, Operand::Symbol { .. })
    }
}

/// A symbolic operation emitted by a [`Thread`] for the embedder to evaluate.
///
/// An `Op` is produced whenever at least one operand is not public, so the
/// computation cannot be performed concretely in-thread. Each variant names
/// the destination [`Reg`] (where applicable) and the symbolic [`Operand`]s
/// involved.
///
/// All [`Reg`]s carried by an `Op` (and by its [`Operand`]s) are **absolute**
/// register indices into the thread's register file, not frame-relative, so an
/// embedder can act on them without tracking per-frame register bases.
///
/// # Load variants
///
/// Load variants carry the resolved effective address as `addr`, together
/// with `concrete` and `symbolic_mask`. For a concrete address, `concrete`
/// holds the public bytes in range (symbolic bytes zeroed) and `symbolic_mask`
/// is the per-byte mask marking which bytes are symbolic, so the embedder can
/// authenticate the symbolic bytes and materialize the concrete ones. For a
/// symbolic address both are zero and the embedder decides how to proceed.
#[derive(Debug, Clone)]
pub enum Op {
    /// Copies the value in `src` to `dst`.
    Copy {
        /// The destination register.
        dst: Reg,
        /// The source register.
        src: Reg,
    },
    /// Reads the global at `global_idx` into `dst`.
    GlobalGet {
        /// The destination register.
        dst: Reg,
        /// The index of the global to read.
        global_idx: u32,
    },
    /// Writes `src` to the global at `global_idx`.
    GlobalSet {
        /// The index of the global to write.
        global_idx: u32,
        /// The value to store.
        src: Operand,
    },
    /// Stores `if_true` into `dst` when `cond` is nonzero, otherwise
    /// `if_false`.
    Select {
        /// The destination register.
        dst: Reg,
        /// The selector; the nonzero/zero condition.
        cond: Operand,
        /// The value chosen when `cond` is nonzero.
        if_true: Operand,
        /// The value chosen when `cond` is zero.
        if_false: Operand,
    },
    /// Applies the unary operation `op` to `src`, storing the result in `dst`.
    Unary {
        /// The destination register.
        dst: Reg,
        /// The unary operation to apply.
        op: mpz_vm_ir::UnaryOp,
        /// The source register.
        src: Reg,
    },
    /// Applies the binary operation `op` to `lhs` and `rhs`, storing the
    /// result in `dst`.
    Binary {
        /// The destination register.
        dst: Reg,
        /// The binary operation to apply.
        op: mpz_vm_ir::BinaryOp,
        /// The left-hand operand.
        lhs: Operand,
        /// The right-hand operand.
        rhs: Operand,
    },
    /// Loads a value from memory. The [`LoadKind`] selects the width and
    /// sign/zero extension.
    Load {
        /// The width and extension of the load.
        kind: mpz_vm_ir::LoadKind,
        /// The destination register.
        dst: Reg,
        /// The effective load address.
        addr: Operand,
        /// The memory immediate (offset and alignment).
        memarg: mpz_vm_ir::MemArg,
        /// The public bytes in range, with symbolic bytes zeroed.
        concrete: u64,
        /// The per-byte mask of which bytes are symbolic.
        symbolic_mask: u8,
    },
    /// Stores a value to memory. The [`StoreKind`] selects the width.
    Store {
        /// The width of the store.
        kind: mpz_vm_ir::StoreKind,
        /// The effective store address.
        addr: Operand,
        /// The value to store.
        val: Operand,
        /// The memory immediate (offset and alignment).
        memarg: mpz_vm_ir::MemArg,
    },
    /// Fills a memory range with a byte value. Emitted when the destination
    /// address is symbolic and not held by this party, so the range cannot be
    /// located locally.
    MemoryFill {
        /// The destination address.
        dest: Operand,
        /// The byte value to write.
        val: Operand,
        /// The number of bytes to write.
        len: Operand,
    },
    /// Copies a memory range. Emitted when the source or destination address is
    /// symbolic and not held by this party.
    MemoryCopy {
        /// The destination address.
        dest: Operand,
        /// The source address.
        src: Operand,
        /// The number of bytes to copy.
        len: Operand,
    },
    /// Initializes a memory range from a data segment. Emitted when the
    /// destination address is symbolic and not held by this party.
    MemoryInit {
        /// The index of the source data segment.
        data_idx: u32,
        /// The destination address.
        dest: Operand,
        /// The offset into the data segment.
        src_offset: Operand,
        /// The number of bytes to copy.
        len: Operand,
    },
}

/// An abstract instruction emitted by a [`Thread`] for the embedder to act on.
///
/// A directive describes a single observable step of execution. Most steps
/// carry an [`Op`] to evaluate, while the remaining variants describe control
/// flow: function calls, returns, branches, and completion.
#[derive(Debug, Clone)]
pub enum Directive {
    /// Invokes the function at `func_idx` with the given `args`.
    Call {
        /// The absolute register to receive the result, if the call returns a
        /// value.
        dst: Option<Reg>,
        /// The index of the function to invoke.
        func_idx: u32,
        /// The call arguments, as absolute register operands.
        args: Vec<Operand>,
        /// The absolute base register of the callee's frame. The `i`-th
        /// argument is bound to the callee's parameter register `param_base +
        /// i`. Unused for host/imported calls, which enter no frame.
        param_base: Reg,
    },
    /// Returns from the current function.
    Return {
        /// The absolute register in the caller that receives the returned
        /// value, or `None` for the outermost return (whose value is the call's
        /// result) or when the result is discarded.
        dst: Option<Reg>,
        /// The absolute register holding the returned value in the returning
        /// frame, if the function returns one.
        src: Option<Reg>,
        /// The returning frame's absolute register range `(base, count)` to
        /// reclaim, or `None` for the outermost return (whose registers hold
        /// the result).
        reclaim: Option<(Reg, u32)>,
    },
    /// Evaluates the symbolic operation `0`.
    Op(Op),
    /// Transfers control to `block` within the function at `func_idx`.
    Branch {
        /// The index of the function containing the target block.
        func_idx: u32,
        /// The block to which control transfers.
        block: BlockId,
        /// The branch condition, if the branch is conditional.
        cond: Option<Operand>,
        /// The block at which a private control-flow region rejoins, if known.
        exit: Option<BlockId>,
        /// Whether the branch is publicly deducible and does not enter a
        /// private control-flow region.
        bail_out: bool,
    },
}
