//! Ideal backend for symbolic execution.

use std::{collections::BTreeMap, ops::Range};

use ir::{BlockId, Function};
use mpz_common::Context as IoContext;
use rangeset::{prelude::*, set::RangeSet};
use serio::{SinkExt, stream::IoStreamExt};

use crate::{
    Directive, Global, Module, Param, Vm, VmError, Write,
    call::Call,
    thread::{Context, StepResult, Thread},
    value::Value,
};

#[derive(Debug, Clone)]
pub enum TraceEvent {
    Directive(Directive),
    PrivateControlFlowStart { func_idx: u32, block: BlockId },
    PrivateControlFlowEnd,
}

/// Internal discriminator used by the pending-diff resolver.
#[derive(Debug, Clone, Copy)]
enum WriteKind {
    Private,
    Blind,
    Public,
    Reveal,
}

pub struct Instance {
    module: Module,
    global: Global,
    /// Pending I/O ops, split across four disjoint range sets. Each
    /// new `write`/`reveal` call evicts the incoming range from the
    /// other three sets and unions it into the target, so the sets
    /// always reflect the resolved last-wins state.
    pending_private: RangeSet<u32>,
    pending_blind: RangeSet<u32>,
    pending_public: RangeSet<u32>,
    pending_reveal: RangeSet<u32>,
    /// Optional trace log for profiling.
    trace_log: Option<Vec<TraceEvent>>,
}

impl Instance {
    pub fn new(module: Module) -> Result<Self, VmError> {
        crate::imports::validate_imports(&module)?;
        let global = Global::new(&module)?;
        Ok(Self {
            module,
            global,
            pending_private: RangeSet::default(),
            pending_blind: RangeSet::default(),
            pending_public: RangeSet::default(),
            pending_reveal: RangeSet::default(),
            trace_log: None,
        })
    }

    pub fn with_tracing(module: Module) -> Result<Self, VmError> {
        let mut inst = Self::new(module)?;
        inst.trace_log = Some(Vec::new());
        Ok(inst)
    }

    pub fn module(&self) -> &Module {
        &self.module
    }
    pub fn global(&self) -> &Global {
        &self.global
    }
    pub fn global_mut(&mut self) -> &mut Global {
        &mut self.global
    }
    pub fn trace_log(&self) -> Option<&[TraceEvent]> {
        self.trace_log.as_deref()
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
    ) -> Result<&ir::LocalFunction, VmError> {
        let func = self
            .module
            .function(func_idx)
            .ok_or(VmError::UndefinedFunction(func_idx))?;
        let func = match func {
            Function::Import(_) => return Err(VmError::InvalidFunction(func_idx)),
            Function::Local(func) => func,
        };
        if func.func_type().results.len() > 1 {
            return Err(VmError::Unsupported("multi-value return".into()));
        }
        if params.len() != func.func_type().params.len() {
            todo!()
        }
        for (arg, expected_ty) in params.iter().zip(&func.func_type().params) {
            if &arg.ty() != expected_ty {
                return Err(VmError::TypeMismatch {
                    expected: *expected_ty,
                    got: arg.ty(),
                });
            }
        }
        Ok(func)
    }

    pub async fn call_with_decode(
        &mut self,
        io: &mut IoContext,
        func_idx: u32,
        params: Vec<Param>,
    ) -> Result<Option<Value>, VmError> {
        self.validate_call(func_idx, &params)?;
        let call = Call {
            func_idx,
            params: params.clone(),
        };
        let mut thread = Thread::new();
        {
            let mut cx = Context {
                module: &self.module,
                global: &mut self.global,
            };
            thread.call(&mut cx, call)?;
        }
        self.flush(&mut thread, io, &params).await?;
        self.run_loop(&mut thread).await
    }

    /// Exchange private/blind values with peer and write resolved values
    /// into Thread's registers.
    async fn flush(
        &mut self,
        thread: &mut Thread,
        io: &mut IoContext,
        params: &[Param],
    ) -> Result<(), VmError> {
        let has_pending_params = params
            .iter()
            .any(|p| matches!(p, Param::Private(_) | Param::Blind(_)));
        let has_pending_memory = self.has_pending_memory();

        if !has_pending_params && !has_pending_memory {
            return Ok(());
        }

        // Exchange param register values.
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
            .map(|f| f.reg_base())
            .unwrap_or(0) as usize;
        let thread_regs = thread.registers_mut();
        for (i, p) in params.iter().enumerate() {
            if let Param::Blind(_) = p {
                let value = received[&(0, i as u32)];
                if thread_base + i < thread_regs.len() {
                    thread_regs[thread_base + i] = value;
                }
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
                let memory = self.global.memory().ok_or(VmError::MemoryNotDefined)?;
                for range in self.pending_private.iter() {
                    let len = (range.end - range.start) as usize;
                    mem_to_send.insert(range.start, memory.read_bytes(range.start, len)?.to_vec());
                }
                for range in self.pending_reveal.iter() {
                    if !self
                        .global
                        .memory_taint()
                        .contains_any(range.start, (range.end - range.start) as usize)
                    {
                        continue;
                    }
                    let len = (range.end - range.start) as usize;
                    mem_to_send.insert(range.start, memory.read_bytes(range.start, len)?.to_vec());
                }
            }

            let recv_ranges: Vec<Range<u32>> = self.pending_blind.iter().collect();

            io.io_mut().send(mem_to_send).await?;
            let received_mem: BTreeMap<u32, Vec<u8>> = io.io_mut().expect_next().await?;

            {
                let memory = self.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                for range in &recv_ranges {
                    let len = (range.end - range.start) as usize;
                    if let Some(data) = received_mem.get(&range.start) {
                        debug_assert_eq!(data.len(), len, "recv region length should match");
                        memory.write_bytes(range.start, data)?;
                    }
                }
            }
        }

        // Taint deltas: Private/Blind become tainted, Public/Reveal
        // become untainted. Collect into scratch vectors to avoid
        // holding simultaneous borrows.
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
            self.global
                .memory_taint_mut()
                .insert_range(range.start, (range.end - range.start) as usize);
        }
        for range in taint_clear {
            self.global
                .memory_taint_mut()
                .remove_range(range.start, (range.end - range.start) as usize);
        }

        self.pending_private.clear();
        self.pending_blind.clear();
        self.pending_public.clear();
        self.pending_reveal.clear();

        Ok(())
    }

    fn dump_error(&self, thread: &Thread, err: &VmError) {
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

    async fn run_loop(&mut self, thread: &mut Thread) -> Result<Option<Value>, VmError> {
        let mut was_in_private_cf = thread.in_private_cf();

        loop {
            let result = {
                let mut cx = Context {
                    module: &self.module,
                    global: &mut self.global,
                };
                match thread.step(&mut cx, true) {
                    Ok(r) => r,
                    Err(e) => {
                        self.dump_error(&thread, &e);
                        return Err(e);
                    }
                }
            };

            match result {
                StepResult::Continue => {}
                StepResult::Directive(directive) => {
                    if let Some(log) = &mut self.trace_log {
                        log.push(TraceEvent::Directive(directive.clone()));
                    }
                    match &directive {
                        Directive::Call { func_idx, .. }
                            if matches!(
                                self.module.function(*func_idx),
                                Some(Function::Import(_))
                            ) =>
                        {
                            todo!("handle host call in run_loop")
                        }
                        _ => {}
                    }
                }
                StepResult::Done { result } => return Ok(result),
            }

            // Track private CF transitions for trace events.
            let in_private_cf = thread.in_private_cf();
            if in_private_cf && !was_in_private_cf {
                if let Some(log) = &mut self.trace_log {
                    if let Some(f) = thread.call_stack().last() {
                        log.push(TraceEvent::PrivateControlFlowStart {
                            func_idx: f.func_idx(),
                            block: f.current_block(),
                        });
                    }
                }
            }
            if !in_private_cf && was_in_private_cf {
                if let Some(log) = &mut self.trace_log {
                    log.push(TraceEvent::PrivateControlFlowEnd);
                }
            }
            was_in_private_cf = in_private_cf;
        }
    }
}

impl Vm for Instance {
    fn write(&mut self, ptr: u32, w: Write<'_>) -> Result<(), VmError> {
        let (kind, len) = match w {
            Write::Private(data) => (WriteKind::Private, data.len()),
            Write::Blind(len) => (WriteKind::Blind, len),
            Write::Public(data) => (WriteKind::Public, data.len()),
        };
        let range = range_for(ptr, len)?;

        // Copy caller-supplied bytes into linear memory eagerly.
        if let Write::Private(data) | Write::Public(data) = w {
            let memory = self.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
            memory.write_bytes(ptr, data)?;
        }

        self.apply_pending(range, kind);
        Ok(())
    }

    fn reveal(&mut self, ptr: u32, len: usize) -> Result<(), VmError> {
        let range = range_for(ptr, len)?;
        self.apply_pending(range, WriteKind::Reveal);
        Ok(())
    }

    fn read(&self, ptr: u32, len: usize) -> Result<&[u8], VmError> {
        if len > 0 {
            if self.global.memory_taint().contains_any(ptr, len) {
                return Err(VmError::Internal(format!(
                    "cannot read tainted memory at {:#x}",
                    ptr
                )));
            }
            let range = ptr..ptr.saturating_add(len as u32);
            if !self.pending_blind.is_disjoint(range) {
                return Err(VmError::Internal(format!(
                    "cannot read pending blind region at {:#x}",
                    ptr
                )));
            }
        }
        let memory = self.global.memory().ok_or(VmError::MemoryNotDefined)?;
        memory.read_bytes(ptr, len)
    }

    async fn call(
        &mut self,
        io: &mut IoContext,
        func_idx: u32,
        params: Vec<Param>,
    ) -> Result<Option<Value>, VmError> {
        self.validate_call(func_idx, &params)?;
        let call = Call {
            func_idx,
            params: params.clone(),
        };
        let mut thread = Thread::new();
        {
            let mut cx = Context {
                module: &self.module,
                global: &mut self.global,
            };
            thread.call(&mut cx, call)?;
        }
        self.flush(&mut thread, io, &params).await?;
        self.run_loop(&mut thread).await
    }
}

fn range_for(ptr: u32, len: usize) -> Result<Range<u32>, VmError> {
    let end = (ptr as u64).checked_add(len as u64);
    match end {
        Some(end) if end <= u32::MAX as u64 => Ok(ptr..end as u32),
        _ => Err(VmError::Internal("memory range overflow".into())),
    }
}
