//! A single-party tracing driver built directly on `mpz-vm-core`.
//!
//! [`Tracer`] runs a [`Module`] to completion while recording every
//! [`Directive`] the thread emits and every private control-flow transition it
//! enters and leaves. It models the party that *holds* every value: private and
//! public inputs are supplied locally, so there is no peer to exchange with and
//! no async I/O. Because the party holds the deciding bits for every branch,
//! indirect call, and `memory.grow`, the thread resolves those locally and
//! never blocks; the only thing left to service are host/imported calls.
//!
//! This is enough to profile op counts, memory traffic, call frequency, and the
//! shape of private control-flow regions, which is all the profiler needs. It
//! deliberately does not implement the two-party value exchange that
//! `mpz-vm-ideal` does.

use std::{collections::BTreeMap, ops::Range};

use mpz_vm_ir::Function;
use rangeset::set::RangeSet;

use mpz_vm_core::{
    Call, Directive, Global, Module, Operand, Param, Trap, Visibility, Write,
    thread::{Pending, StepResult, Thread},
    value::Value,
};

/// One observable event in a profiled execution.
#[derive(Debug, Clone)]
pub enum TraceEvent {
    /// A directive emitted by the thread.
    Directive(Directive),
    /// Execution entered a private control-flow region.
    PrivateControlFlowStart,
    /// Execution left the current private control-flow region.
    PrivateControlFlowEnd,
}

/// The result of running a benchmark function to completion.
pub enum Outcome {
    /// The call returned, optionally with a value.
    Returned(Option<Value>),
    /// The call trapped.
    Trapped(Trap),
}

/// Errors raised while staging inputs or driving execution.
#[derive(Debug, thiserror::Error)]
pub enum TracerError {
    /// An interpreter or instantiation fault from `mpz-vm-core`.
    #[error(transparent)]
    Core(#[from] mpz_vm_core::Error),
    /// A memory access trapped while staging an input or servicing a host call.
    #[error("trap: {0}")]
    Trap(Trap),
    /// A write targeted a module that declares no linear memory.
    #[error("memory not defined")]
    MemoryNotDefined,
    /// The guest called an import the tracer does not service.
    #[error("unsupported import: {0}")]
    UnsupportedImport(String),
    /// Execution blocked on a value the holding party should have resolved
    /// locally (a symbolic branch, indirect call, or `memory.grow`).
    #[error("blocked on unresolved {0}; the holding party should resolve it locally")]
    Blocked(&'static str),
    /// An invariant the tracer relies on was violated.
    #[error("internal: {0}")]
    Internal(String),
}

/// Internal discriminator for staged writes.
#[derive(Clone, Copy)]
enum WriteKind {
    Private,
    Blind,
    Public,
}

/// A reveal staged by a guest `vc::reveal_*` call, keyed by the handle returned
/// to the guest and resolved by the matching `*_wait`.
enum RevealEntry {
    /// A scalar reveal; `wait` returns this value.
    Scalar(Value),
    /// A byte-range reveal; `wait` marks `[ptr, ptr + len)` public.
    Bytes { ptr: u32, len: usize },
}

/// A single-party VM instance that records a trace as it runs.
pub struct Tracer {
    module: Module,
    global: Global,
    pending_private: RangeSet<u32>,
    pending_blind: RangeSet<u32>,
    pending_public: RangeSet<u32>,
    reveal_handles: BTreeMap<i32, RevealEntry>,
    next_reveal_handle: i32,
    trace: Vec<TraceEvent>,
}

impl Tracer {
    /// Creates a tracer for `module`, initializing its global state.
    pub fn new(module: Module) -> Result<Self, TracerError> {
        let global = Global::new(&module)?;
        Ok(Self {
            module,
            global,
            pending_private: RangeSet::default(),
            pending_blind: RangeSet::default(),
            pending_public: RangeSet::default(),
            reveal_handles: BTreeMap::new(),
            next_reveal_handle: 0,
            trace: Vec::new(),
        })
    }

    /// Returns the module this tracer was created from.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Returns the events recorded so far.
    pub fn trace(&self) -> &[TraceEvent] {
        &self.trace
    }

    /// Stages a [`Write`] of bytes at `ptr` for the next [`call`](Self::call).
    ///
    /// Private and public bytes are copied into linear memory immediately; a
    /// blind region only reserves the range (its bytes are not held by this
    /// party and stay zeroed). Staging a region overrides any previous pending
    /// visibility for the overlapping bytes.
    pub fn write(&mut self, ptr: u32, w: Write<'_>) -> Result<(), TracerError> {
        let (kind, len) = match w {
            Write::Private(data) => (WriteKind::Private, data.len()),
            Write::Blind(len) => (WriteKind::Blind, len),
            Write::Public(data) => (WriteKind::Public, data.len()),
        };
        let range = range_for(ptr, len)?;

        if let Write::Private(data) | Write::Public(data) = w {
            let memory = self.global.memory_mut().ok_or(TracerError::MemoryNotDefined)?;
            memory.write_bytes(ptr, data).map_err(TracerError::Trap)?;
        }

        self.apply_pending(range, kind);
        Ok(())
    }

    /// Calls the function at `func_idx` with `params` and runs it to completion,
    /// recording a trace along the way.
    pub fn call(&mut self, func_idx: u32, params: Vec<Param>) -> Result<Outcome, TracerError> {
        self.flush_taint();

        let mut thread = Thread::new();
        thread.call(&self.module, &mut self.global, Call { func_idx, params })?;
        self.run_loop(&mut thread)
    }

    /// Applies staged visibility to linear memory. The holding party owns every
    /// value, so this is a purely local taint update with no peer exchange:
    /// private and blind ranges become symbolic, public ranges concrete.
    fn flush_taint(&mut self) {
        let to_set: Vec<Range<u32>> = self
            .pending_private
            .iter()
            .chain(self.pending_blind.iter())
            .collect();
        let to_clear: Vec<Range<u32>> = self.pending_public.iter().collect();

        for range in to_set {
            let len = (range.end - range.start) as usize;
            self.global
                .set_memory_visibility(range.start, len, Visibility::Private);
        }
        for range in to_clear {
            let len = (range.end - range.start) as usize;
            self.global
                .set_memory_visibility(range.start, len, Visibility::Public);
        }

        self.pending_private.clear();
        self.pending_blind.clear();
        self.pending_public.clear();
    }

    fn apply_pending(&mut self, range: Range<u32>, target: WriteKind) {
        if range.start >= range.end {
            return;
        }
        self.pending_private.difference_mut(range.clone());
        self.pending_blind.difference_mut(range.clone());
        self.pending_public.difference_mut(range.clone());
        match target {
            WriteKind::Private => self.pending_private.union_mut(range),
            WriteKind::Blind => self.pending_blind.union_mut(range),
            WriteKind::Public => self.pending_public.union_mut(range),
        }
    }

    fn run_loop(&mut self, thread: &mut Thread) -> Result<Outcome, TracerError> {
        let mut was_private = thread.in_private_cf();

        loop {
            match thread.step(&self.module, &mut self.global)? {
                StepResult::Continue => {}
                // An imported call surfaces as a `Directive::Call` with a pending
                // host call set. Service it now so the next step proceeds, then
                // record the directive in order.
                StepResult::Directive(Directive::Call {
                    dst,
                    func_idx,
                    args,
                    param_base,
                }) if is_import(&self.module, func_idx) => {
                    self.service_host_call(thread, func_idx, &args)?;
                    self.trace.push(TraceEvent::Directive(Directive::Call {
                        dst,
                        func_idx,
                        args,
                        param_base,
                    }));
                }
                StepResult::Directive(directive) => {
                    self.trace.push(TraceEvent::Directive(directive));
                }
                StepResult::Trapped { trap, .. } => return Ok(Outcome::Trapped(trap)),
                StepResult::Done { result, .. } => return Ok(Outcome::Returned(result)),
                StepResult::Blocked(Pending::HostCall { .. }) => {
                    return Err(TracerError::Internal(
                        "host call surfaced as blocked; it should be serviced at its directive"
                            .into(),
                    ));
                }
                StepResult::Blocked(Pending::Branch) => return Err(TracerError::Blocked("branch")),
                StepResult::Blocked(Pending::CallIndirect { .. }) => {
                    return Err(TracerError::Blocked("indirect call"));
                }
                StepResult::Blocked(Pending::MemoryGrow { .. }) => {
                    return Err(TracerError::Blocked("memory.grow"));
                }
            }

            // Record private control-flow transitions.
            let now_private = thread.in_private_cf();
            if now_private && !was_private {
                self.trace.push(TraceEvent::PrivateControlFlowStart);
            } else if !now_private && was_private {
                self.trace.push(TraceEvent::PrivateControlFlowEnd);
            }
            was_private = now_private;
        }
    }

    /// Services a host/imported call surfaced as a [`Pending::HostCall`],
    /// resolving it so execution can continue. Implements the small set of WASI
    /// and VCI imports the ideal VM supports; anything else is an error.
    fn service_host_call(
        &mut self,
        thread: &mut Thread,
        func_idx: u32,
        args: &[Operand],
    ) -> Result<(), TracerError> {
        let (module, name) = match self.module.function(func_idx) {
            Some(Function::Import(import)) => {
                (import.module().to_string(), import.name().to_string())
            }
            _ => return Err(TracerError::Internal("host call to non-import function".into())),
        };
        let arg_value = |i: usize| -> Option<Value> {
            match args.get(i) {
                Some(Operand::Concrete(v)) | Some(Operand::Symbol { value: Some(v), .. }) => Some(*v),
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
                let memory = self.global.memory_mut().ok_or(TracerError::MemoryNotDefined)?;
                let mut total = 0u32;
                for i in 0..iovs_len {
                    let iov = iovs + i * 8;
                    let pb = memory.read_bytes(iov, 4).map_err(TracerError::Trap)?;
                    let ptr = u32::from_le_bytes([pb[0], pb[1], pb[2], pb[3]]);
                    let lb = memory.read_bytes(iov + 4, 4).map_err(TracerError::Trap)?;
                    let len = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]);
                    if fd == 1 || fd == 2 {
                        let data = memory.read_bytes(ptr, len as usize).map_err(TracerError::Trap)?;
                        if let Ok(s) = std::str::from_utf8(data) {
                            eprint!("{s}");
                        }
                    }
                    total += len;
                }
                memory
                    .write_bytes(nwritten_ptr, &total.to_le_bytes())
                    .map_err(TracerError::Trap)?;
                thread.resolve_host_call(Some(Value::from(0i32)), Visibility::Public)?;
                Ok(())
            }
            ("wasi_snapshot_preview1", "proc_exit") => Err(TracerError::Trap(Trap::Unreachable)),
            ("vc", "reveal_i32" | "reveal_i64" | "reveal_f32" | "reveal_f64") => {
                let value = arg_value(0).ok_or_else(|| {
                    TracerError::Internal(format!("{name}: revealed value is unavailable"))
                })?;
                let handle = self.alloc_reveal_handle(RevealEntry::Scalar(value));
                thread.resolve_host_call(Some(Value::from(handle)), Visibility::Public)?;
                Ok(())
            }
            ("vc", "reveal_bytes") => {
                let ptr = arg_i32(0) as u32;
                let len = arg_i32(1) as usize;
                let handle = self.alloc_reveal_handle(RevealEntry::Bytes { ptr, len });
                thread.resolve_host_call(Some(Value::from(handle)), Visibility::Public)?;
                Ok(())
            }
            ("vc", "reveal_i32_wait" | "reveal_i64_wait" | "reveal_f32_wait" | "reveal_f64_wait") => {
                let handle = arg_i32(0);
                match self.reveal_handles.remove(&handle) {
                    Some(RevealEntry::Scalar(value)) => {
                        thread.resolve_host_call(Some(value), Visibility::Public)?;
                        Ok(())
                    }
                    _ => Err(TracerError::Internal(format!(
                        "{name}: no scalar reveal for handle {handle}"
                    ))),
                }
            }
            ("vc", "reveal_bytes_wait") => {
                let handle = arg_i32(0);
                match self.reveal_handles.remove(&handle) {
                    Some(RevealEntry::Bytes { ptr, len }) => {
                        self.global.set_memory_visibility(ptr, len, Visibility::Public);
                        thread.resolve_host_call(None, Visibility::Public)?;
                        Ok(())
                    }
                    _ => Err(TracerError::Internal(format!(
                        "reveal_bytes_wait: no byte reveal for handle {handle}"
                    ))),
                }
            }
            _ => Err(TracerError::UnsupportedImport(format!("{module}::{name}"))),
        }
    }

    fn alloc_reveal_handle(&mut self, entry: RevealEntry) -> i32 {
        let handle = self.next_reveal_handle;
        self.next_reveal_handle += 1;
        self.reveal_handles.insert(handle, entry);
        handle
    }
}

fn is_import(module: &Module, func_idx: u32) -> bool {
    matches!(module.function(func_idx), Some(Function::Import(_)))
}

fn range_for(ptr: u32, len: usize) -> Result<Range<u32>, TracerError> {
    let len =
        u32::try_from(len).map_err(|_| TracerError::Internal("write length exceeds u32".into()))?;
    let end = ptr
        .checked_add(len)
        .ok_or_else(|| TracerError::Internal("write range overflows u32".into()))?;
    Ok(ptr..end)
}
