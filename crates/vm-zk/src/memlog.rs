//! Ordered, byte-granular log of a chunk's memory accesses.
//!
//! [`MemoryLog`] records every load and store in execution order, each with
//! its position in the chunk's access sequence. This is the *schedule* of the
//! chunk's memory traffic — addresses, widths, kinds, and symbolic masks —
//! which both parties derive identically from the directive skeleton. It
//! serves two consumers today and one to come:
//!
//! - capture reads the written-byte view ([`written_addrs`](MemoryLog::written_addrs))
//!   to know which bytes a boundary snapshot must record, draining it at each
//!   mark ([`take_written`](MemoryLog::take_written)) so snapshots are
//!   per-segment deltas;
//! - the segment scan drains the written-byte states ([`take_written`](MemoryLog::take_written))
//!   to lay out the memory part of each delta boundary commitment;
//! - a future RAM argument consumes the full access log
//!   ([`accesses`](MemoryLog::accesses)): each entry becomes an
//!   `(op, addr, time)` tuple whose value wires are attached during replay,
//!   with a permutation proof checking read-after-write consistency. That
//!   also subsumes boundary memory commitments and lifts the public-address
//!   restriction, since consistency no longer rides on resolving addresses
//!   at capture time.
//!
//! Wasm linear memory is byte-addressed and stores have partial widths, so an
//! arbitrary trace cut preserves only byte granularity: a later `store8` may
//! overwrite one byte of an earlier 4-byte store. The written-byte view is
//! therefore tracked per byte.

use std::collections::BTreeMap;

use mpz_vm_core::{Operand, value::Value};
use mpz_vm_ir::{LoadKind, MemArg, StoreKind};

use crate::error::{Result, ZkVmError};

/// What a store wrote, as far as the proof is concerned.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Stored {
    /// An authenticated value: the bytes carry wires.
    Symbolic,
    /// A public value: both parties know the bytes.
    Public(Value),
}

/// The state of one written byte.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ByteState {
    Symbolic,
    Public(u8),
}

/// Whether an access reads or writes memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessKind {
    Read,
    Write,
}

/// One logged memory access.
// The access log's consumer is the future RAM argument; nothing reads the
// entries yet.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Access {
    /// Position in the chunk's access sequence: the RAM-argument timestamp.
    pub(crate) index: u32,
    pub(crate) kind: AccessKind,
    /// Effective byte address of the first accessed byte.
    pub(crate) addr: u32,
    /// Access width in bytes.
    pub(crate) width: u32,
    /// Which accessed bytes carry wires, LSB = `addr`: a load's symbolic
    /// mask, or all accessed bytes for a symbolic store (none for a public
    /// one).
    pub(crate) symbolic_mask: u8,
}

/// Ordered log of the memory accesses in a chunk.
#[derive(Debug, Clone, Default)]
pub(crate) struct MemoryLog {
    accesses: Vec<Access>,
    /// Net per-byte effect of the writes so far, in address order.
    written: BTreeMap<u32, ByteState>,
}

impl MemoryLog {
    /// Records a store of `kind` at effective address `eff` writing the low
    /// `store_width(kind)` bytes of the stored value.
    pub(crate) fn record_store(&mut self, kind: StoreKind, eff: u32, stored: Stored) {
        let width = store_width(kind);
        let symbolic_mask = match stored {
            Stored::Symbolic => ((1u16 << width) - 1) as u8,
            Stored::Public(_) => 0,
        };
        self.push(AccessKind::Write, eff, width, symbolic_mask);
        match stored {
            Stored::Symbolic => {
                for b in 0..width {
                    self.written.insert(eff + b, ByteState::Symbolic);
                }
            }
            Stored::Public(v) => {
                let le = v.to_le_bytes();
                for b in 0..width {
                    self.written
                        .insert(eff + b, ByteState::Public(le[b as usize]));
                }
            }
        }
    }

    /// Records a load of `kind` at effective address `eff`. `symbolic_mask`
    /// is the directive's: which loaded bytes come from authenticated memory
    /// rather than the public `concrete` value.
    pub(crate) fn record_load(&mut self, kind: LoadKind, eff: u32, symbolic_mask: u8) {
        self.push(AccessKind::Read, eff, load_width(kind), symbolic_mask);
    }

    fn push(&mut self, kind: AccessKind, addr: u32, width: u32, symbolic_mask: u8) {
        self.accesses.push(Access {
            index: self.accesses.len() as u32,
            kind,
            addr,
            width,
            symbolic_mask,
        });
    }

    /// Every access so far, in execution order.
    #[allow(dead_code)]
    pub(crate) fn accesses(&self) -> &[Access] {
        &self.accesses
    }

    /// Whether any byte has been written since the last drain.
    pub(crate) fn has_writes(&self) -> bool {
        !self.written.is_empty()
    }

    /// The byte addresses written since the last drain, ascending.
    pub(crate) fn written_addrs(&self) -> impl Iterator<Item = u32> + '_ {
        self.written.keys().copied()
    }

    /// Drains the written-byte view, returning the net per-byte effect of the
    /// writes since the last drain (in address order). Capture and the
    /// segment scan drain at each mark, so each boundary covers only its own
    /// segment's writes; the access log is unaffected.
    pub(crate) fn take_written(&mut self) -> BTreeMap<u32, ByteState> {
        std::mem::take(&mut self.written)
    }
}

/// The effective byte address of a memory access: `addr + memarg.offset`.
///
/// zk-vm memory addresses must be public; a symbolic address is unsupported
/// (until accesses are checked by a RAM argument instead of resolved at
/// capture time).
pub(crate) fn eff_addr(addr: &Operand, memarg: &MemArg) -> Result<u32> {
    match addr {
        Operand::Concrete(Value::I32(a)) => Ok((*a as u64 + memarg.offset as u64) as u32),
        Operand::Symbol { .. } => Err(ZkVmError::Unsupported(
            "zk-vm: symbolic memory address not supported".into(),
        )),
        other => Err(ZkVmError::Internal(format!(
            "memory address operand is not i32: {other:?}"
        ))),
    }
}

/// Bytes written by a store of `kind`: the access width, not the value width.
pub(crate) fn store_width(kind: StoreKind) -> u32 {
    use StoreKind::*;
    match kind {
        I32Store8 | I64Store8 => 1,
        I32Store16 | I64Store16 => 2,
        I32 | F32 | I64Store32 => 4,
        I64 | F64 => 8,
    }
}

/// Bytes read by a load of `kind`: the access width, not the result width.
pub(crate) fn load_width(kind: LoadKind) -> u32 {
    use LoadKind::*;
    match kind {
        I32Load8U | I32Load8S | I64Load8U | I64Load8S => 1,
        I32Load16U | I32Load16S | I64Load16U | I64Load16S => 2,
        I32 | F32 | I64Load32U | I64Load32S => 4,
        I64 | F64 => 8,
    }
}
