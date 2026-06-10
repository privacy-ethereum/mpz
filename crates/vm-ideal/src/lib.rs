//! An ideal-functionality implementation of the [`Vm`] trait.
//!
//! This crate provides [`Instance`], a single-party reference VM that executes
//! a [`Module`] with full knowledge of every value. Where a real multi-party
//! protocol would keep private and blind inputs secret and only learn shared
//! values through interaction, the ideal functionality holds every value
//! locally and merely simulates the value exchange over an I/O channel. It is
//! intended for testing and as an executable specification of VM semantics.

use std::{collections::BTreeMap, ops::Range};

use mpz_common::Context as IoContext;
use mpz_vm_ir::{FuncType, Function, ValType};
use rangeset::{prelude::*, set::RangeSet};
use serio::{SinkExt, stream::IoStreamExt};

use mpz_vm_core::{
    Call, Directive, Error as CoreError, Global, Module, Operand, Param, Trap, Visibility, Vm,
    Write,
    thread::{Pending, StepResult, Thread},
    value::Value,
};

/// The error type reported by the ideal [`Vm`] implementation.
#[derive(Debug, thiserror::Error)]
pub enum IdealError {
    /// An interpreter or instantiation fault from `mpz-vm-core`.
    #[error(transparent)]
    Core(#[from] CoreError),

    /// A runtime trap aborted execution.
    #[error("trap: {0}")]
    Trap(Trap),

    /// A value of type `got` was found where `expected` was required.
    #[error("type mismatch: expected {expected:?}, got {got:?}")]
    TypeMismatch {
        /// The required type.
        expected: ValType,
        /// The actual type.
        got: ValType,
    },

    /// A feature the ideal VM does not support was requested.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The module imports a function the ideal VM does not service.
    #[error("unsupported import: {module}::{name}")]
    UnsupportedImport {
        /// The import's module name.
        module: String,
        /// The import's field name.
        name: String,
    },

    /// A serviced import was declared with an unexpected signature.
    #[error("import signature mismatch: {name}")]
    ImportSignatureMismatch {
        /// The import's field name.
        name: String,
    },

    /// An I/O operation over the coordination channel failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A local-only call ([`Vm::call_local`]) reached work that requires
    /// communication with another party.
    #[error("operation requires communication: {0}")]
    RequiresCommunication(String),

    /// An invariant of the ideal VM was violated, indicating a bug.
    #[error("internal error: {0}")]
    Internal(String),
}

impl IdealError {
    /// Returns `true` if this error reflects a feature the ideal VM does not
    /// support (used by the spec harness to skip rather than fail).
    pub fn is_expected_unsupported(&self) -> bool {
        matches!(
            self,
            IdealError::Unsupported(_)
                | IdealError::UnsupportedImport { .. }
                | IdealError::Core(CoreError::Unimplemented(_))
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum WriteKind {
    Private,
    Blind,
    Public,
    Reveal,
}

/// An ideal-functionality [`Vm`] instance bound to a single [`Module`].
///
/// An `Instance` owns the module's [`Global`] state. Inputs supplied through
/// [`write`](Vm::write) and reveals requested through [`reveal`](Vm::reveal)
/// are staged and not exchanged until the next [`call`](Vm::call), after which
/// execution runs to completion locally because every value is available to the
/// ideal functionality.
pub struct Instance {
    module: Module,
    global: Global,
    pending_private: RangeSet<u32>,
    pending_blind: RangeSet<u32>,
    pending_public: RangeSet<u32>,
    pending_reveal: RangeSet<u32>,
    reveal_handles: BTreeMap<i32, RevealEntry>,
    next_reveal_handle: i32,
}

/// A reveal staged by a guest `vc::reveal_*` call, keyed by the handle returned
/// to the guest and resolved by the matching `*_wait`.
enum RevealEntry {
    /// A scalar reveal; `wait` returns this value.
    Scalar(Value),
    /// A byte-range reveal; `wait` marks `[ptr, ptr + len)` public.
    Bytes {
        /// The start of the revealed range.
        ptr: u32,
        /// The length of the revealed range, in bytes.
        len: usize,
    },
}

impl Instance {
    /// Creates an instance for the given [`Module`].
    ///
    /// The module's imports are validated and its [`Global`] state is
    /// initialized.
    ///
    /// # Errors
    ///
    /// Returns a [`IdealError`] if the module declares an unsupported or
    /// invalid import, or if the global state cannot be initialized.
    pub fn new(module: Module) -> Result<Self, IdealError> {
        validate_imports(&module)?;
        let global = Global::new(&module)?;
        Ok(Self {
            module,
            global,
            pending_private: RangeSet::default(),
            pending_blind: RangeSet::default(),
            pending_public: RangeSet::default(),
            pending_reveal: RangeSet::default(),
            reveal_handles: BTreeMap::new(),
            next_reveal_handle: 0,
        })
    }

    /// Returns the [`Module`] this instance was created from.
    pub fn module(&self) -> &Module {
        &self.module
    }

    fn apply_pending(&mut self, range: Range<u32>, target: WriteKind) {
        if range.start >= range.end {
            return;
        }
        self.pending_private.difference_mut(range.clone());
        self.pending_blind.difference_mut(range.clone());
        self.pending_public.difference_mut(range.clone());
        self.pending_reveal.difference_mut(range.clone());
        match target {
            WriteKind::Private => self.pending_private.union_mut(range),
            WriteKind::Blind => self.pending_blind.union_mut(range),
            WriteKind::Public => self.pending_public.union_mut(range),
            WriteKind::Reveal => self.pending_reveal.union_mut(range),
        }
    }

    fn has_pending_memory(&self) -> bool {
        !self.pending_private.is_empty()
            || !self.pending_blind.is_empty()
            || !self.pending_public.is_empty()
            || !self.pending_reveal.is_empty()
    }

    fn validate_call(
        &self,
        func_idx: u32,
        params: &[Param],
    ) -> Result<&mpz_vm_ir::LocalFunction, IdealError> {
        let func = self
            .module
            .function(func_idx)
            .ok_or(IdealError::Core(CoreError::UndefinedFunction(func_idx)))?;
        let func = match func {
            Function::Import(_) => {
                return Err(IdealError::Core(CoreError::InvalidFunction(func_idx)));
            }
            Function::Local(func) => func,
        };
        if func.func_type().results.len() > 1 {
            return Err(IdealError::Unsupported("multi-value return".into()));
        }
        if params.len() != func.func_type().params.len() {
            todo!()
        }
        for (arg, expected_ty) in params.iter().zip(&func.func_type().params) {
            if &arg.ty() != expected_ty {
                return Err(IdealError::TypeMismatch {
                    expected: *expected_ty,
                    got: arg.ty(),
                });
            }
        }
        Ok(func)
    }

    async fn flush(
        &mut self,
        thread: &mut Thread,
        io: &mut IoContext,
        params: &[Param],
    ) -> Result<(), IdealError> {
        let has_pending_params = params
            .iter()
            .any(|p| matches!(p, Param::Private(_) | Param::Blind(_)));
        let has_pending_memory = self.has_pending_memory();

        if !has_pending_params && !has_pending_memory {
            return Ok(());
        }

        let to_send: BTreeMap<(usize, u32), Value> = params
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                if let Param::Private(v) = p {
                    Some(((0, i as u32), *v))
                } else {
                    None
                }
            })
            .collect();

        io.io_mut().send(to_send).await?;
        let received: BTreeMap<(usize, u32), Value> = io.io_mut().expect_next().await?;

        let thread_base = thread
            .call_stack()
            .last()
            .map(|f| f.reg_base().index())
            .unwrap_or(0);
        {
            let thread_regs = thread.registers_mut();
            for (i, p) in params.iter().enumerate() {
                if let Param::Blind(_) = p {
                    let value = received[&(0, i as u32)];
                    if thread_base + i < thread_regs.len() {
                        thread_regs[thread_base + i] = value;
                    }
                }
            }
        }
        // The ideal functionality shares all values: a received blind input is
        // now held, so mark it available (it stays symbolic for taint purposes).
        for (i, p) in params.iter().enumerate() {
            if let Param::Blind(_) = p {
                thread.set_register_available((thread_base + i) as u32);
            }
        }

        // Assemble the memory exchange from the four pending range
        // sets. Bytes for Private/Reveal are read live from linear
        // memory (Private was copied in eagerly by `write`; Reveal
        // reads whatever has accumulated since). Skip entirely if
        // there is no pending memory work, to avoid requiring a
        // linear memory in modules that don't declare one.
        if has_pending_memory {
            let mut mem_to_send: BTreeMap<u32, Vec<u8>> = BTreeMap::new();

            {
                let memory = self
                    .global
                    .memory()
                    .ok_or(IdealError::Core(CoreError::MemoryNotDefined))?;
                for range in self.pending_private.iter() {
                    let len = (range.end - range.start) as usize;
                    mem_to_send.insert(
                        range.start,
                        memory
                            .read_bytes(range.start, len)
                            .map_err(IdealError::Trap)?
                            .to_vec(),
                    );
                }
                for range in self.pending_reveal.iter() {
                    if !self
                        .global
                        .memory_tainted(range.start, (range.end - range.start) as usize)
                    {
                        continue;
                    }
                    let len = (range.end - range.start) as usize;
                    mem_to_send.insert(
                        range.start,
                        memory
                            .read_bytes(range.start, len)
                            .map_err(IdealError::Trap)?
                            .to_vec(),
                    );
                }
            }

            let recv_ranges: Vec<Range<u32>> = self.pending_blind.iter().collect();

            io.io_mut().send(mem_to_send).await?;
            let received_mem: BTreeMap<u32, Vec<u8>> = io.io_mut().expect_next().await?;

            {
                let memory = self
                    .global
                    .memory_mut()
                    .ok_or(IdealError::Core(CoreError::MemoryNotDefined))?;
                for range in &recv_ranges {
                    let len = (range.end - range.start) as usize;
                    if let Some(data) = received_mem.get(&range.start) {
                        debug_assert_eq!(data.len(), len, "recv region length should match");
                        memory
                            .write_bytes(range.start, data)
                            .map_err(IdealError::Trap)?;
                    }
                }
            }
        }

        // Visibility deltas. Private/Blind ranges become symbolic; the ideal
        // functionality holds every value (its own private writes and the
        // received blind bytes), so they are `Private` (symbolic + held).
        // Public/Reveal ranges become `Public` (concrete). Collected into
        // scratch vectors to avoid holding simultaneous borrows.
        let taint_set: Vec<Range<u32>> = self
            .pending_private
            .iter()
            .chain(self.pending_blind.iter())
            .collect();
        let taint_clear: Vec<Range<u32>> = self
            .pending_public
            .iter()
            .chain(self.pending_reveal.iter())
            .collect();
        for range in taint_set {
            self.global.set_memory_visibility(
                range.start,
                (range.end - range.start) as usize,
                Visibility::Private,
            );
        }
        for range in taint_clear {
            self.global.set_memory_visibility(
                range.start,
                (range.end - range.start) as usize,
                Visibility::Public,
            );
        }

        self.pending_private.clear();
        self.pending_blind.clear();
        self.pending_public.clear();
        self.pending_reveal.clear();

        Ok(())
    }

    fn dump_error(&self, thread: &Thread, err: &IdealError) {
        eprintln!("VM error: {err:?}");
        eprintln!("Call stack:");
        for (i, frame) in thread.call_stack().iter().rev().enumerate() {
            let name = self
                .module
                .function_names()
                .get(&frame.func_idx())
                .map(|s| s.as_str())
                .unwrap_or("<unknown>");
            eprintln!(
                "  {i}: {name} (func_idx={}, block={:?}, ip={})",
                frame.func_idx(),
                frame.current_block(),
                frame.ip()
            );
        }
    }

    /// Stages a reveal under a fresh handle and returns that handle.
    fn alloc_reveal_handle(&mut self, entry: RevealEntry) -> i32 {
        let handle = self.next_reveal_handle;
        self.next_reveal_handle += 1;
        self.reveal_handles.insert(handle, entry);
        handle
    }

    /// Services a host/imported call surfaced by the thread as a
    /// [`Pending::HostCall`], resolving it so execution can continue.
    ///
    /// The ideal VM implements a small set of WASI and VCI imports; anything
    /// else is reported as [`IdealError::Unsupported`].
    fn service_host_call(
        &mut self,
        thread: &mut Thread,
        func_idx: u32,
        args: &[Operand],
    ) -> Result<(), IdealError> {
        let (module, name) = match self.module.function(func_idx) {
            Some(Function::Import(import)) => {
                (import.module().to_string(), import.name().to_string())
            }
            _ => {
                return Err(IdealError::Internal(
                    "host call to non-import function".into(),
                ));
            }
        };
        let arg_value = |i: usize| -> Option<Value> {
            match args.get(i) {
                Some(Operand::Concrete(v)) | Some(Operand::Symbol { value: Some(v), .. }) => {
                    Some(*v)
                }
                _ => None,
            }
        };
        let arg_i32 = |i: usize| -> i32 { arg_value(i).and_then(|v| v.as_i32().ok()).unwrap_or(0) };
        match (module.as_str(), name.as_str()) {
            ("wasi_snapshot_preview1", "fd_write") => {
                let fd = arg_i32(0);
                let iovs = arg_i32(1) as u32;
                let iovs_len = arg_i32(2) as u32;
                let nwritten_ptr = arg_i32(3) as u32;
                let memory = self
                    .global
                    .memory_mut()
                    .ok_or(IdealError::Core(CoreError::MemoryNotDefined))?;
                let mut total = 0u32;
                for i in 0..iovs_len {
                    let iov = iovs + i * 8;
                    let pb = memory.read_bytes(iov, 4).map_err(IdealError::Trap)?;
                    let ptr = u32::from_le_bytes([pb[0], pb[1], pb[2], pb[3]]);
                    let lb = memory.read_bytes(iov + 4, 4).map_err(IdealError::Trap)?;
                    let len = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]);
                    if fd == 1 || fd == 2 {
                        let data = memory
                            .read_bytes(ptr, len as usize)
                            .map_err(IdealError::Trap)?;
                        if let Ok(s) = std::str::from_utf8(data) {
                            eprint!("{s}");
                        }
                    }
                    total += len;
                }
                memory
                    .write_bytes(nwritten_ptr, &total.to_le_bytes())
                    .map_err(IdealError::Trap)?;
                thread.resolve_host_call(Some(Value::from(0i32)), Visibility::Public)?;
                Ok(())
            }
            ("wasi_snapshot_preview1", "proc_exit") => Err(IdealError::Trap(Trap::Unreachable)),
            // Scalar reveal: stage the revealed value under a fresh handle. The
            // ideal functionality already holds it, so disclosure is local.
            ("vc", "reveal_i32" | "reveal_i64" | "reveal_f32" | "reveal_f64") => {
                let value = arg_value(0).ok_or_else(|| {
                    IdealError::Internal(format!("{name}: revealed value is unavailable"))
                })?;
                let handle = self.alloc_reveal_handle(RevealEntry::Scalar(value));
                thread.resolve_host_call(Some(Value::from(handle)), Visibility::Public)?;
                Ok(())
            }
            // Byte-range reveal: stage the range under a fresh handle.
            ("vc", "reveal_bytes") => {
                let ptr = arg_i32(0) as u32;
                let len = arg_i32(1) as usize;
                let handle = self.alloc_reveal_handle(RevealEntry::Bytes { ptr, len });
                thread.resolve_host_call(Some(Value::from(handle)), Visibility::Public)?;
                Ok(())
            }
            // Scalar wait: return the staged value, now public.
            (
                "vc",
                "reveal_i32_wait" | "reveal_i64_wait" | "reveal_f32_wait" | "reveal_f64_wait",
            ) => {
                let handle = arg_i32(0);
                match self.reveal_handles.remove(&handle) {
                    Some(RevealEntry::Scalar(value)) => {
                        thread.resolve_host_call(Some(value), Visibility::Public)?;
                        Ok(())
                    }
                    _ => Err(IdealError::Internal(format!(
                        "{name}: no scalar reveal for handle {handle}"
                    ))),
                }
            }
            // Byte wait: mark the staged range public; the bytes are already in
            // place. Resolves with no value.
            ("vc", "reveal_bytes_wait") => {
                let handle = arg_i32(0);
                match self.reveal_handles.remove(&handle) {
                    Some(RevealEntry::Bytes { ptr, len }) => {
                        self.global
                            .set_memory_visibility(ptr, len, Visibility::Public);
                        thread.resolve_host_call(None, Visibility::Public)?;
                        Ok(())
                    }
                    _ => Err(IdealError::Internal(format!(
                        "reveal_bytes_wait: no byte reveal for handle {handle}"
                    ))),
                }
            }
            _ => Err(IdealError::Unsupported(format!(
                "import not serviced by the ideal VM: {module}::{name}"
            ))),
        }
    }

    async fn run_loop(&mut self, thread: &mut Thread) -> Result<Option<Value>, IdealError> {
        loop {
            let result = match thread.step(&self.module, &mut self.global) {
                Ok(r) => r,
                Err(e) => {
                    let e: IdealError = e.into();
                    self.dump_error(thread, &e);
                    return Err(e);
                }
            };

            match result {
                StepResult::Continue | StepResult::Directive(_) => {}
                StepResult::Trapped { trap, .. } => return Err(IdealError::Trap(trap)),
                StepResult::Blocked(Pending::HostCall { func_idx, args, .. }) => {
                    self.service_host_call(thread, func_idx, &args)?;
                }
                StepResult::Blocked(
                    Pending::Branch | Pending::CallIndirect { .. } | Pending::MemoryGrow { .. },
                ) => {
                    // The ideal functionality holds every value (private inputs
                    // are shared on exchange), so symbolic branches, indirect-call
                    // indices, and grow counts are always evaluated locally and
                    // never block here. (Could-trap ops no longer block at all.)
                    return Err(IdealError::Internal(
                        "ideal loop blocked on a condition that should be locally \
                         resolvable; all values should be available to the ideal \
                         functionality"
                            .into(),
                    ));
                }
                StepResult::Done { result, .. } => return Ok(result),
            }
        }
    }

    /// Runs `thread` to completion using only local work, rejecting any step
    /// that would require communication in a real multi-party backend.
    ///
    /// Host calls are still serviced (the ideal functionality holds every
    /// value, so reveals are local), but a symbolic [`Op`], a private branch,
    /// or a block on an unheld value reports
    /// [`IdealError::RequiresCommunication`].
    fn run_loop_local(&mut self, thread: &mut Thread) -> Result<Option<Value>, IdealError> {
        loop {
            let result = match thread.step(&self.module, &mut self.global) {
                Ok(r) => r,
                Err(e) => {
                    let e: IdealError = e.into();
                    self.dump_error(thread, &e);
                    return Err(e);
                }
            };

            match result {
                StepResult::Continue => {}
                // Control-flow directives (local calls, returns, public branches)
                // are in-thread bookkeeping; a symbolic op or private branch is
                // not locally resolvable in a real backend.
                StepResult::Directive(Directive::Op(_)) => {
                    return Err(IdealError::RequiresCommunication(
                        "symbolic operation requires communication".into(),
                    ));
                }
                StepResult::Directive(Directive::Branch {
                    cond: Some(Operand::Symbol { .. }),
                    ..
                }) => {
                    return Err(IdealError::RequiresCommunication(
                        "private branch requires communication".into(),
                    ));
                }
                StepResult::Directive(_) => {}
                StepResult::Blocked(Pending::HostCall { func_idx, args, .. }) => {
                    self.service_host_call(thread, func_idx, &args)?;
                }
                StepResult::Blocked(_) => {
                    return Err(IdealError::RequiresCommunication(
                        "execution blocked on a value not held locally".into(),
                    ));
                }
                StepResult::Trapped { trap, .. } => return Err(IdealError::Trap(trap)),
                StepResult::Done { result, .. } => return Ok(result),
            }
        }
    }
}

impl Vm for Instance {
    type Error = IdealError;

    /// Stages a [`Write`] of `len` bytes at `ptr` for the next exchange.
    ///
    /// The destination region is recorded as pending with the visibility
    /// implied by `w`. For [`Write::Private`] and [`Write::Public`] the
    /// supplied bytes are copied into linear memory immediately; for
    /// [`Write::Blind`] only the region is reserved, to be filled in during
    /// the exchange. Staging a region overrides any previous pending
    /// visibility for the overlapping bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IdealError::Internal`] if the region `ptr..ptr + len`
    /// overflows the address space, or [`IdealError::Core`] if the module
    /// has no linear memory to receive the bytes.
    fn write(&mut self, ptr: u32, w: Write<'_>) -> Result<(), IdealError> {
        let (kind, len) = match w {
            Write::Private(data) => (WriteKind::Private, data.len()),
            Write::Blind(len) => (WriteKind::Blind, len),
            Write::Public(data) => (WriteKind::Public, data.len()),
        };
        let range = range_for(ptr, len)?;

        if let Write::Private(data) | Write::Public(data) = w {
            let memory = self
                .global
                .memory_mut()
                .ok_or(IdealError::Core(CoreError::MemoryNotDefined))?;
            memory.write_bytes(ptr, data).map_err(IdealError::Trap)?;
        }

        self.apply_pending(range, kind);
        Ok(())
    }

    /// Stages a region of `len` bytes at `ptr` to be revealed at the next
    /// exchange.
    ///
    /// The region is marked pending so that its current contents become public
    /// during the exchange. Staging a region overrides any previous pending
    /// visibility for the overlapping bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IdealError::Internal`] if the region `ptr..ptr + len`
    /// overflows the address space.
    fn reveal(&mut self, ptr: u32, len: usize) -> Result<(), IdealError> {
        let range = range_for(ptr, len)?;
        self.apply_pending(range, WriteKind::Reveal);
        Ok(())
    }

    /// Returns the `len` bytes of linear memory starting at `ptr`.
    ///
    /// Only fully public, settled memory may be read: the region must contain
    /// no symbolic (tainted) bytes and must not overlap a pending blind
    /// region whose contents have not yet been received.
    ///
    /// # Errors
    ///
    /// Returns [`IdealError::Internal`] if the region is symbolic or overlaps a
    /// pending blind region, [`IdealError::Core`] if the module has no
    /// linear memory, or [`IdealError::Trap`] if the region is out of bounds.
    fn read(&self, ptr: u32, len: usize) -> Result<&[u8], IdealError> {
        if len > 0 {
            if self.global.memory_tainted(ptr, len) {
                return Err(IdealError::Internal(format!(
                    "cannot read tainted memory at {:#x}",
                    ptr
                )));
            }
            let range = ptr..ptr.saturating_add(len as u32);
            if !self.pending_blind.is_disjoint(range) {
                return Err(IdealError::Internal(format!(
                    "cannot read pending blind region at {:#x}",
                    ptr
                )));
            }
        }
        let memory = self
            .global
            .memory()
            .ok_or(IdealError::Core(CoreError::MemoryNotDefined))?;
        memory.read_bytes(ptr, len).map_err(IdealError::Trap)
    }

    /// Calls the function at `func_idx` with `params` and runs it to
    /// completion.
    ///
    /// Any pending memory regions and private or blind parameters are exchanged
    /// over `io` before execution begins; the ideal functionality then runs the
    /// call locally, since every value is available to it. Returns the call's
    /// single result, or [`None`] if the function returns nothing.
    ///
    /// # Errors
    ///
    /// Returns a [`IdealError`] if `func_idx` does not name a callable local
    /// function, if `params` do not match the function's signature, if the
    /// exchange over `io` fails, or if execution traps.
    async fn call(
        &mut self,
        io: &mut IoContext,
        func_idx: u32,
        params: Vec<Param>,
    ) -> Result<Option<Value>, IdealError> {
        self.validate_call(func_idx, &params)?;
        let call = Call {
            func_idx,
            params: params.clone(),
        };
        let mut thread = Thread::new();
        thread.call(&self.module, &mut self.global, call)?;
        self.flush(&mut thread, io, &params).await?;
        self.run_loop(&mut thread).await
    }

    /// Flushes any pending memory regions over `io` without running a function.
    ///
    /// Staged private, blind, public, and reveal regions are exchanged exactly
    /// as the next [`call`](Vm::call) would, leaving nothing pending. Returns
    /// immediately when there is no pending memory.
    ///
    /// # Errors
    ///
    /// Returns a [`IdealError`] if the exchange over `io` fails or the module
    /// has no linear memory to exchange.
    async fn commit(&mut self, io: &mut IoContext) -> Result<(), IdealError> {
        if !self.has_pending_memory() {
            return Ok(());
        }
        // No call is in progress, so there are no private/blind parameters to
        // exchange; `flush` runs the memory exchange against a fresh thread.
        let mut thread = Thread::new();
        self.flush(&mut thread, io, &[]).await
    }

    /// Calls the function at `func_idx` with `params`, running it to completion
    /// using only local work.
    ///
    /// Pending public writes are settled locally; private, blind, or reveal
    /// regions must first be flushed with [`commit`](Vm::commit), and `params`
    /// must be public. Execution then runs with no communication.
    ///
    /// # Errors
    ///
    /// Returns [`IdealError::RequiresCommunication`] if `params` carry private
    /// or blind values, if any private/blind/reveal region is still pending, or
    /// if execution reaches a step that is not locally resolvable. Otherwise
    /// returns a [`IdealError`] for an invalid `func_idx`, a signature
    /// mismatch, or a trap.
    fn call_local(
        &mut self,
        func_idx: u32,
        params: Vec<Param>,
    ) -> Result<Option<Value>, IdealError> {
        self.validate_call(func_idx, &params)?;
        if params
            .iter()
            .any(|p| matches!(p, Param::Private(_) | Param::Blind(_)))
        {
            return Err(IdealError::RequiresCommunication(
                "call_local requires public params; private or blind inputs must be exchanged via call".into(),
            ));
        }
        if !self.pending_private.is_empty()
            || !self.pending_blind.is_empty()
            || !self.pending_reveal.is_empty()
        {
            return Err(IdealError::RequiresCommunication(
                "pending private, blind, or reveal memory must be flushed with commit before call_local".into(),
            ));
        }

        // Pending public writes need no exchange: their bytes are already in
        // memory; settle their visibility locally and clear the queue.
        let public_ranges: Vec<Range<u32>> = self.pending_public.iter().collect();
        for range in public_ranges {
            self.global.set_memory_visibility(
                range.start,
                (range.end - range.start) as usize,
                Visibility::Public,
            );
        }
        self.pending_public.clear();

        let mut thread = Thread::new();
        thread.call(&self.module, &mut self.global, Call { func_idx, params })?;
        self.run_loop_local(&mut thread)
    }
}

fn range_for(ptr: u32, len: usize) -> Result<Range<u32>, IdealError> {
    let end = (ptr as u64).checked_add(len as u64);
    match end {
        Some(end) if end <= u32::MAX as u64 => Ok(ptr..end as u32),
        _ => Err(IdealError::Internal("memory range overflow".into())),
    }
}

/// Validates that every function imported by `module` is one the ideal VM
/// services and is declared with the expected signature.
///
/// Import validation is an embedder concern: this set is exactly what
/// [`Instance::service_host_call`] handles.
///
/// # Errors
///
/// Returns [`IdealError::UnsupportedImport`] for an import the ideal VM does
/// not service, or [`IdealError::ImportSignatureMismatch`] for a serviced
/// import declared with an unexpected signature.
fn validate_imports(module: &Module) -> Result<(), IdealError> {
    for func in module.functions() {
        let Function::Import(import) = func else {
            continue;
        };
        let expected = match (import.module(), import.name()) {
            // WASI.
            ("wasi_snapshot_preview1", "fd_write") => FuncType {
                params: vec![ValType::I32; 4],
                results: vec![ValType::I32],
            },
            ("wasi_snapshot_preview1", "proc_exit") => FuncType {
                params: vec![ValType::I32],
                results: vec![],
            },
            // VCI scalar reveal: `reveal_<ty>(value) -> handle`.
            ("vc", "reveal_i32") => FuncType {
                params: vec![ValType::I32],
                results: vec![ValType::I32],
            },
            ("vc", "reveal_i64") => FuncType {
                params: vec![ValType::I64],
                results: vec![ValType::I32],
            },
            ("vc", "reveal_f32") => FuncType {
                params: vec![ValType::F32],
                results: vec![ValType::I32],
            },
            ("vc", "reveal_f64") => FuncType {
                params: vec![ValType::F64],
                results: vec![ValType::I32],
            },
            // VCI scalar wait: `reveal_<ty>_wait(handle) -> value`.
            ("vc", "reveal_i32_wait") => FuncType {
                params: vec![ValType::I32],
                results: vec![ValType::I32],
            },
            ("vc", "reveal_i64_wait") => FuncType {
                params: vec![ValType::I32],
                results: vec![ValType::I64],
            },
            ("vc", "reveal_f32_wait") => FuncType {
                params: vec![ValType::I32],
                results: vec![ValType::F32],
            },
            ("vc", "reveal_f64_wait") => FuncType {
                params: vec![ValType::I32],
                results: vec![ValType::F64],
            },
            // VCI byte-range reveal.
            ("vc", "reveal_bytes") => FuncType {
                params: vec![ValType::I32, ValType::I32],
                results: vec![ValType::I32],
            },
            ("vc", "reveal_bytes_wait") => FuncType {
                params: vec![ValType::I32],
                results: vec![],
            },
            _ => {
                return Err(IdealError::UnsupportedImport {
                    module: import.module().to_string(),
                    name: import.name().to_string(),
                });
            }
        };

        if import.func_type() != &expected {
            return Err(IdealError::ImportSignatureMismatch {
                name: import.name().to_string(),
            });
        }
    }
    Ok(())
}
