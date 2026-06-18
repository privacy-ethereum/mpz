//! Segmentation of a captured chunk for parallel proving.
//!
//! A chunk's directive trace is split at the [`SegmentMark`]s recorded during
//! capture. Each segment is committed and folded by an independent worker;
//! the workers are stitched together at the marks by *boundary commitments*:
//! the boundary after segment `j` is a *delta* — only the registers, globals,
//! and memory bytes written during segment `j` are freshly committed on the
//! tape (plus tombstones for registers the segment reclaimed). Worker `j`
//! asserts that its final wires for those items equal the delta commitment,
//! and worker `j + 1` seeds its state by materializing every prior delta in
//! order, directly off the tape ([`mpz_zk_core::prover_wire`] /
//! [`mpz_zk_core::verifier_wire`]), so no wire ever crosses between workers.
//! An item last written in segment `i` reaches every later worker as the
//! same materialized delta-`i` wire, so cross-segment equality holds by
//! construction and only a segment's own writes ever need committing —
//! total boundary tape is linear in the chunk's writes rather than
//! quadratic.
//!
//! [`plan`] derives the layout purely from the directive skeleton plus the
//! symbolic types of pre-existing (persistent) state, so the prover and
//! verifier compute identical layouts. Only the boundary *values* are
//! prover-side data, resolved from the capture [`Snapshot`]s.

use std::collections::BTreeMap;
use std::ops::Range;

use mpz_circuits::Context;
use mpz_fields::gf2::Gf2;
use mpz_fields::gf2_128::Gf2_128;
use mpz_vm_core::{Directive, Op, Operand, Param, Reg, ValType, value::Value};
use mpz_vm_ir::{BinaryOp, LoadKind, Module, UnaryOp};
use mpz_vm_memory::{AuthState, AuthValue, Bit, Byte};

use crate::{
    capture::{ChunkCapture, SegmentMark, Snapshot, is_import},
    commit::{ty_width, value_le_bits},
    cost,
    error::{Result, ZkVmError},
    host::RevealEvent,
    memlog::{self, ByteState, MemoryLog, Stored},
};

/// The chunk's parallel-proving layout: per-segment directive, tape, and
/// challenge ranges, with the stitch boundaries between them.
#[derive(Debug)]
pub(crate) struct Plan {
    pub(crate) segments: Vec<Segment>,
    /// Total execute-tape entries: segment gate/advice entries plus boundary
    /// commitments. Excludes any input-commit prefix and the VOPE tail.
    pub(crate) tape_len: usize,
}

#[derive(Debug)]
pub(crate) struct Segment {
    /// Directive range in the chunk trace.
    pub(crate) directives: Range<usize>,
    /// Reveal-action range (one action per imported call in `directives`).
    pub(crate) reveals: Range<usize>,
    /// Tape entries consumed by this segment's gates and advice, relative to
    /// the start of the chunk's execute region.
    pub(crate) tape: Range<usize>,
    /// AND gates preceding this segment: the challenge-stream offset.
    pub(crate) chi_gates: usize,
    /// The boundary committed after this segment; `None` for the last.
    pub(crate) boundary: Option<Boundary>,
}

/// A stitch boundary: the committed delta of one segment — every register,
/// global, and memory byte written during that segment, plus tombstones for
/// the registers it reclaimed.
#[derive(Debug)]
pub(crate) struct Boundary {
    /// Tape entries of the symbolic items' commitments, relative to the start
    /// of the chunk's execute region.
    pub(crate) tape: Range<usize>,
    pub(crate) items: Vec<Item>,
    /// Register ranges reclaimed during the segment, in trace order. Applied
    /// (before `items`) when seeding a later worker, mirroring the sequential
    /// `drop_range` a single replay would have performed.
    pub(crate) dropped: Vec<(Reg, u32)>,
    /// Prover-side plaintext at the boundary; `None` on the verifier.
    pub(crate) snapshot: Option<Snapshot>,
}

/// One stitched state item. Symbolic items consume tape entries (in `items`
/// order); public items are rematerialized from their known value.
#[derive(Debug)]
pub(crate) enum Item {
    Reg { reg: Reg, ty: ValType },
    Global { idx: u32, ty: ValType },
    Mem { addr: u32 },
    PubReg { reg: Reg, value: Value },
    PubGlobal { idx: u32, value: Value },
    PubMem { addr: u32, value: u8 },
}

impl Item {
    /// Tape entries this item consumes (0 for public items).
    fn tape_bits(&self) -> usize {
        match self {
            Item::Reg { ty, .. } | Item::Global { ty, .. } => ty_width(*ty),
            Item::Mem { .. } => 8,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone)]
enum RegState {
    Sym(ValType),
    Pub(Value),
}

/// Scan state mirroring the `AuthState` updates `replay` performs, tracking
/// only which items the chunk has written and whether they are symbolic.
///
/// `pre_regs` holds the registers the input-commit prefix installs before any
/// segment runs (the call's committed params); they resolve like persistent
/// state and never enter a boundary unless overwritten.
///
/// `regs`/`globals` are chunk-cumulative and drive operand resolution; the
/// `seg_*` fields accumulate the *current segment's* writes and reclaims and
/// are drained into a delta [`Boundary`] at each mark.
#[derive(Debug, Default)]
struct Scan {
    pre_regs: BTreeMap<u32, ValType>,
    regs: BTreeMap<u32, RegState>,
    globals: BTreeMap<u32, RegState>,
    mem: MemoryLog,
    seg_regs: BTreeMap<u32, RegState>,
    seg_globals: BTreeMap<u32, RegState>,
    seg_dropped: Vec<(Reg, u32)>,
}

impl Scan {
    fn reg(&self, auth: &AuthState, reg: Reg) -> Result<RegState> {
        self.try_reg(auth, reg)
            .ok_or(ZkVmError::RegAuthMissing { reg })
    }

    /// Like [`reg`](Self::reg), but `None` when the register has no auth
    /// state anywhere — a register holding a public value tracked only by the
    /// thread. Mirrors `Registers::copy`, which silently skips such sources.
    fn try_reg(&self, auth: &AuthState, reg: Reg) -> Option<RegState> {
        if let Some(s) = self.regs.get(&reg.0) {
            return Some(s.clone());
        }
        if let Some(ty) = self.pre_regs.get(&reg.0) {
            return Some(RegState::Sym(*ty));
        }
        auth.regs.get(reg).map(|av| RegState::Sym(av.ty()))
    }

    fn operand(&self, auth: &AuthState, op: &Operand) -> Result<RegState> {
        match op {
            Operand::Symbol { reg, .. } => self.reg(auth, *reg),
            Operand::Concrete(v) => Ok(RegState::Pub(*v)),
        }
    }

    /// Records a register write into both the cumulative and segment views.
    fn set_reg(&mut self, reg: u32, s: RegState) {
        self.regs.insert(reg, s.clone());
        self.seg_regs.insert(reg, s);
    }

    /// Records a global write into both the cumulative and segment views.
    fn set_global(&mut self, idx: u32, s: RegState) {
        self.globals.insert(idx, s.clone());
        self.seg_globals.insert(idx, s);
    }

    /// Records a frame reclaim: the range leaves both views and a tombstone
    /// enters the segment delta so later workers drop it at seeding.
    fn reclaim(&mut self, base: Reg, count: u32) {
        for r in base.0..base.0 + count {
            self.regs.remove(&r);
            self.seg_regs.remove(&r);
        }
        self.seg_dropped.push((base, count));
    }

    /// Drains the current segment's writes and reclaims into delta boundary
    /// items, resetting the segment views for the next segment.
    ///
    /// Items the thread no longer considers symbolic at the mark are dropped:
    /// public computation overwrites registers, globals, and revealed memory
    /// without emitting directives, so the auth wire behind such an item is
    /// dead — every later use of the value surfaces as a concrete operand —
    /// and committing it would assert a stale wire against the fresh
    /// plaintext.
    fn take_boundary(&mut self, mark: &SegmentMark) -> (Vec<Item>, Vec<(Reg, u32)>) {
        let mut items = Vec::new();
        for (r, s) in std::mem::take(&mut self.seg_regs) {
            match s {
                RegState::Sym(ty) if mark.sym_regs.binary_search(&r).is_ok() => {
                    items.push(Item::Reg { reg: Reg(r), ty });
                }
                RegState::Sym(_) => {}
                RegState::Pub(value) => items.push(Item::PubReg { reg: Reg(r), value }),
            }
        }
        for (g, s) in std::mem::take(&mut self.seg_globals) {
            match s {
                RegState::Sym(ty) if mark.sym_globals.binary_search(&g).is_ok() => {
                    items.push(Item::Global { idx: g, ty });
                }
                RegState::Sym(_) => {}
                RegState::Pub(value) => items.push(Item::PubGlobal { idx: g, value }),
            }
        }
        for (a, s) in self.mem.take_written() {
            match s {
                ByteState::Symbolic if mark.pub_mem.binary_search(&a).is_err() => {
                    items.push(Item::Mem { addr: a });
                }
                ByteState::Symbolic => {}
                ByteState::Public(value) => items.push(Item::PubMem { addr: a, value }),
            }
        }
        (items, std::mem::take(&mut self.seg_dropped))
    }
}

/// Derives the chunk's segmentation layout.
///
/// Deterministic in the directive skeleton, the reveal actions, and the
/// symbolic types of the persistent `auth` state, all of which the prover and
/// verifier share.
///
/// With no segment marks the chunk is one segment and needs no layout scan.
/// A trace the scan cannot mirror (e.g. one that replay will reject anyway)
/// also degrades to a single sequential segment, so the proving pass surfaces
/// the same error at the same protocol point on both sides.
#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(segments = tracing::field::Empty, tape_len = tracing::field::Empty)
)]
pub(crate) fn plan(
    chunk: &ChunkCapture,
    module: &Module,
    auth: &AuthState,
    params: &[Param],
    root_reg_base: Reg,
) -> Plan {
    let plan = if chunk.marks.is_empty() {
        single_segment(chunk)
    } else {
        match scan_plan(chunk, module, auth, params, root_reg_base) {
            Ok(plan) => plan,
            Err(e) => {
                tracing::warn!(error = %e, "segment scan failed; falling back to one segment");
                single_segment(chunk)
            }
        }
    };
    let span = tracing::Span::current();
    span.record("segments", plan.segments.len());
    span.record("tape_len", plan.tape_len);
    plan
}

fn single_segment(chunk: &ChunkCapture) -> Plan {
    Plan {
        segments: vec![Segment {
            directives: 0..chunk.trace.len(),
            reveals: 0..chunk.reveal_actions.len(),
            tape: 0..chunk.cost,
            chi_gates: 0,
            boundary: None,
        }],
        tape_len: chunk.cost,
    }
}

fn scan_plan(
    chunk: &ChunkCapture,
    module: &Module,
    auth: &AuthState,
    params: &[Param],
    root_reg_base: Reg,
) -> Result<Plan> {
    let mut scan = Scan::default();
    for (i, p) in params.iter().enumerate() {
        let ty = match p {
            Param::Private(v) => v.ty(),
            Param::Blind(ty) => *ty,
            Param::Public(_) => continue,
        };
        scan.pre_regs.insert(root_reg_base.0 + i as u32, ty);
    }

    // Per-segment accumulators.
    let mut seg_dir_start = 0usize;
    let mut seg_rev_start = 0usize;
    let mut seg_bits = 0usize;
    let mut seg_gates = 0usize;

    // (directives, reveals, tape_bits, gates, boundary delta+snapshot)
    type RawSeg = (
        Range<usize>,
        Range<usize>,
        usize,
        usize,
        Option<(Vec<Item>, Vec<(Reg, u32)>, Option<Snapshot>)>,
    );
    let mut raw: Vec<RawSeg> = Vec::new();

    let mut marks = chunk.marks.iter().peekable();
    let mut reveal_cursor = 0usize;

    for (i, directive) in chunk.trace.iter().enumerate() {
        match directive {
            Directive::Op(op) => {
                let bits = cost::op_cost(op)?;
                let advice = cost::op_advice_bits(op);
                seg_bits += bits;
                seg_gates += bits - advice;
                scan_op(&mut scan, auth, op)?;
            }
            Directive::Call {
                func_idx,
                args,
                param_base,
                ..
            } => {
                if is_import(module, *func_idx) {
                    let action = chunk.reveal_actions.get(reveal_cursor).ok_or_else(|| {
                        ZkVmError::Internal("reveal action missing for imported call".into())
                    })?;
                    reveal_cursor += 1;
                    scan_reveal(&mut scan, action);
                } else {
                    for (k, arg) in args.iter().enumerate() {
                        if let Operand::Symbol { reg, .. } = arg
                            && let Some(s) = scan.try_reg(auth, *reg)
                        {
                            scan.set_reg(param_base.0 + k as u32, s);
                        }
                    }
                }
            }
            Directive::Return { dst, src, reclaim } => {
                if let (Some(d), Some(s)) = (dst, src)
                    && let Some(st) = scan.try_reg(auth, *s)
                {
                    scan.set_reg(d.0, st);
                }
                if let Some((base, count)) = reclaim {
                    scan.reclaim(*base, *count);
                }
            }
            Directive::Branch { .. } => {}
        }

        // A mark splits the trace *after* directive `i`.
        if marks.peek().is_some_and(|m| m.directive_idx == i + 1) {
            let mark = marks.next().expect("peeked");
            let (items, dropped) = scan.take_boundary(mark);
            raw.push((
                seg_dir_start..i + 1,
                seg_rev_start..reveal_cursor,
                seg_bits,
                seg_gates,
                Some((items, dropped, mark.snapshot.clone())),
            ));
            seg_dir_start = i + 1;
            seg_rev_start = reveal_cursor;
            seg_bits = 0;
            seg_gates = 0;
        }
    }
    raw.push((
        seg_dir_start..chunk.trace.len(),
        seg_rev_start..reveal_cursor,
        seg_bits,
        seg_gates,
        None,
    ));

    // Lay the tape out: [seg 1][boundary 1][seg 2][boundary 2]…[seg S].
    let mut segments = Vec::with_capacity(raw.len());
    let mut offset = 0usize;
    let mut chi = 0usize;
    for (directives, reveals, bits, gates, boundary) in raw {
        let tape = offset..offset + bits;
        offset += bits;
        let chi_gates = chi;
        chi += gates;
        let boundary = boundary.map(|(items, dropped, snapshot)| {
            let len: usize = items.iter().map(Item::tape_bits).sum();
            let tape = offset..offset + len;
            offset += len;
            Boundary {
                tape,
                items,
                dropped,
                snapshot,
            }
        });
        segments.push(Segment {
            directives,
            reveals,
            tape,
            chi_gates,
            boundary,
        });
    }

    Ok(Plan {
        segments,
        tape_len: offset,
    })
}

fn scan_op(scan: &mut Scan, auth: &AuthState, op: &Op) -> Result<()> {
    match op {
        Op::Copy { dst, src } => {
            // `Registers::copy` semantics: no-op when the source carries no
            // auth state (a public value tracked only by the thread).
            if let Some(s) = scan.try_reg(auth, *src) {
                scan.set_reg(dst.0, s);
            }
        }
        Op::GlobalGet { dst, global_idx } => {
            let s = if let Some(s) = scan.globals.get(global_idx) {
                s.clone()
            } else {
                auth.globals
                    .get(Reg(*global_idx))
                    .map(|av| RegState::Sym(av.ty()))
                    .ok_or(ZkVmError::GlobalAuthMissing { idx: *global_idx })?
            };
            scan.set_reg(dst.0, s);
        }
        Op::GlobalSet { global_idx, src } => {
            let s = scan.operand(auth, src)?;
            scan.set_global(*global_idx, s);
        }
        Op::Binary { dst, op, .. } => {
            scan.set_reg(dst.0, RegState::Sym(binary_result_ty(*op)));
        }
        Op::Unary { dst, op, .. } => {
            scan.set_reg(dst.0, RegState::Sym(unary_result_ty(*op)));
        }
        Op::Load {
            dst,
            kind,
            addr,
            memarg,
            symbolic_mask,
            ..
        } => {
            let eff = memlog::eff_addr(addr, memarg)?;
            scan.mem.record_load(*kind, eff, *symbolic_mask);
            scan.set_reg(dst.0, RegState::Sym(load_result_ty(*kind)));
        }
        Op::Store {
            kind,
            addr,
            val,
            memarg,
        } => {
            let eff = memlog::eff_addr(addr, memarg)?;
            let stored = match scan.operand(auth, val)? {
                RegState::Sym(_) => Stored::Symbolic,
                RegState::Pub(v) => Stored::Public(v),
            };
            scan.mem.record_store(*kind, eff, stored);
        }
        _ => return Err(crate::error::unsupported_op(op)),
    }
    Ok(())
}

fn scan_reveal(scan: &mut Scan, action: &RevealEvent) {
    match action {
        RevealEvent::OpenScalar { handle_dst, id, .. } => {
            scan.set_reg(handle_dst.0, RegState::Pub(Value::I32(*id as i32)));
        }
        RevealEvent::WaitScalar { dst, value } => {
            scan.set_reg(dst.0, RegState::Pub(*value));
        }
        RevealEvent::OpenBytes { handle_dst, id, .. } => {
            scan.set_reg(handle_dst.0, RegState::Pub(Value::I32(*id as i32)));
        }
        RevealEvent::WaitBytes => {}
    }
}

fn binary_result_ty(op: BinaryOp) -> ValType {
    use BinaryOp::*;
    match op {
        // Comparisons always produce i32.
        I64Eq | I64Ne | I64LtS | I64LtU | I64GtS | I64GtU | I64LeS | I64LeU | I64GeS | I64GeU => {
            ValType::I32
        }
        I64Add | I64Sub | I64Mul | I64And | I64Or | I64Xor | I64Shl | I64ShrS | I64ShrU
        | I64Rotl | I64Rotr | I64DivU | I64RemU | I64DivS | I64RemS => ValType::I64,
        _ => ValType::I32,
    }
}

fn unary_result_ty(op: UnaryOp) -> ValType {
    use UnaryOp::*;
    match op {
        I64Clz | I64Ctz | I64Popcnt | I64ExtendI32S | I64ExtendI32U | I64Extend8S
        | I64Extend16S | I64Extend32S => ValType::I64,
        _ => ValType::I32,
    }
}

fn load_result_ty(kind: LoadKind) -> ValType {
    use LoadKind::*;
    match kind {
        I64 | I64Load8U | I64Load8S | I64Load16U | I64Load16S | I64Load32U | I64Load32S => {
            ValType::I64
        }
        _ => ValType::I32,
    }
}

// ============================================================
// Boundary materialization
// ============================================================

/// The prover-side plaintext of a boundary's symbolic items, one bit per tape
/// entry, in `items` order.
pub(crate) fn boundary_bits(boundary: &Boundary) -> Result<Vec<bool>> {
    let snapshot = boundary
        .snapshot
        .as_ref()
        .ok_or_else(|| ZkVmError::Internal("boundary snapshot missing on prover".into()))?;
    let mut bits = Vec::with_capacity(boundary.tape.len());
    for item in &boundary.items {
        match item {
            Item::Reg { reg, ty } => {
                let v = snapshot.regs.get(reg.0 as usize).copied().ok_or_else(|| {
                    ZkVmError::Internal(format!("snapshot missing register {reg}"))
                })?;
                bits.extend(value_le_bits(v, ty_width(*ty)));
            }
            Item::Global { idx, ty } => {
                let v = snapshot
                    .globals
                    .get(*idx as usize)
                    .copied()
                    .ok_or_else(|| ZkVmError::Internal(format!("snapshot missing global {idx}")))?;
                bits.extend(value_le_bits(v, ty_width(*ty)));
            }
            Item::Mem { addr } => {
                let b = *snapshot.mem.get(addr).ok_or_else(|| {
                    ZkVmError::Internal(format!("snapshot missing byte {addr:#x}"))
                })?;
                bits.extend((0..8).map(|i| (b >> i) & 1 != 0));
            }
            _ => {}
        }
    }
    Ok(bits)
}

/// Installs one delta boundary's effect into `auth`. A worker seeds its
/// starting state by applying every boundary before its segment, in order;
/// reclaims apply first so a reclaim-then-rewrite within the segment nets to
/// the rewrite. `wires` holds one wire per symbolic tape entry (already
/// materialized from the tape); `pub_bit` materializes a public-bit wire.
pub(crate) fn apply_boundary(
    auth: &mut AuthState,
    boundary: &Boundary,
    wires: &[Gf2_128],
    pub_bit: &dyn Fn(bool) -> Gf2_128,
) -> Result<()> {
    for (base, count) in &boundary.dropped {
        auth.regs.drop_range(*base, *count);
    }
    let mut k = 0usize;
    let mut take = |n: usize| -> Vec<Bit> {
        let out = wires[k..k + n].iter().map(|w| Bit(*w)).collect();
        k += n;
        out
    };
    for item in &boundary.items {
        match item {
            Item::Reg { reg, ty } => {
                let bits = take(ty_width(*ty));
                auth.regs.set(*reg, AuthValue::from_bits(*ty, &bits)?);
            }
            Item::Global { idx, ty } => {
                let bits = take(ty_width(*ty));
                auth.globals
                    .set(Reg(*idx), AuthValue::from_bits(*ty, &bits)?);
            }
            Item::Mem { addr } => {
                let bits = take(8);
                auth.memory
                    .set_byte(*addr, Byte::new(core::array::from_fn(|i| bits[i])));
            }
            Item::PubReg { reg, value } => {
                auth.regs.set(*reg, pub_value(*value, pub_bit)?);
            }
            Item::PubGlobal { idx, value } => {
                auth.globals.set(Reg(*idx), pub_value(*value, pub_bit)?);
            }
            Item::PubMem { addr, value } => {
                auth.memory.set_byte(
                    *addr,
                    Byte::new(core::array::from_fn(|i| {
                        Bit(pub_bit((value >> i) & 1 != 0))
                    })),
                );
            }
        }
    }
    debug_assert_eq!(k, wires.len());
    Ok(())
}

/// Asserts that the worker's final wires for every symbolic item its own
/// segment wrote equal the delta commitment `wires`, stitching this segment
/// to the rest of the chunk. Items written by earlier segments need no
/// assertion: this worker and every later one hold the same materialized
/// delta wires for them by construction.
pub(crate) fn assert_boundary<C>(
    auth: &AuthState,
    boundary: &Boundary,
    wires: &[Gf2_128],
    ctx: &mut C,
) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: std::fmt::Debug,
{
    let mut k = 0usize;
    let mut assert_wires = |ctx: &mut C, state: &[Bit], n: usize, item: &Item| -> Result<()> {
        for i in 0..n {
            ctx.assert_eq(state[i].0, wires[k + i]).map_err(|e| {
                ZkVmError::Internal(format!(
                    "boundary assert at {item:?} bit {i}: wire lsb {} vs committed lsb {} ({e:?})",
                    state[i].0.to_inner() & 1,
                    wires[k + i].to_inner() & 1,
                ))
            })?;
        }
        k += n;
        Ok(())
    };
    for item in &boundary.items {
        match item {
            Item::Reg { reg, ty } => {
                let av = auth
                    .regs
                    .get(*reg)
                    .ok_or(ZkVmError::RegAuthMissing { reg: *reg })?;
                assert_wires(ctx, av.bits(), ty_width(*ty), item)?;
            }
            Item::Global { idx, ty } => {
                let av = auth
                    .globals
                    .get(Reg(*idx))
                    .ok_or(ZkVmError::GlobalAuthMissing { idx: *idx })?;
                assert_wires(ctx, av.bits(), ty_width(*ty), item)?;
            }
            Item::Mem { addr } => {
                let byte = auth
                    .memory
                    .get_byte(*addr)
                    .ok_or(ZkVmError::MemAuthMissing { addr: *addr })?;
                assert_wires(ctx, byte.bits(), 8, item)?;
            }
            // Public items are rematerialized identically by both parties at
            // worker seeding; nothing to bind.
            _ => {}
        }
    }
    debug_assert_eq!(k, wires.len());
    Ok(())
}

fn pub_value(value: Value, pub_bit: &dyn Fn(bool) -> Gf2_128) -> Result<AuthValue> {
    let ty = value.ty();
    let bits: Vec<Bit> = value_le_bits(value, ty_width(ty))
        .into_iter()
        .map(|b| Bit(pub_bit(b)))
        .collect();
    Ok(AuthValue::from_bits(ty, &bits)?)
}
