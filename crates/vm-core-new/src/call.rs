use std::{collections::BTreeMap, sync::Arc, task::Poll};

use ir::{Function, Instruction, LocalFunction, Module, ValType};

use crate::{
    HostState, OperandStack, State, Trace, Trap, VmError, arithmetic,
    ops::{HostFnId, SymbolicOp, SymbolicOps},
    trace::TraceBuilder,
    value::{IValue, Value, ValueState},
};

/// Result of attempting to fold an arithmetic operation.
enum FoldResult {
    /// Operation folds to a concrete value (e.g., x * 0 = 0).
    Clear(Value),
    /// Operation is identity - result is operand at given index (e.g., x + 0 =
    /// x).
    Identity(usize),
    /// Cannot fold - must emit trace instruction.
    None,
    /// Operation caused an error (e.g., divide by zero trap).
    Error(VmError),
}

/// Try to fold an arithmetic operation with the given operands.
fn try_fold(op: &ir::InstructionArith, operands: &[IValue]) -> FoldResult {
    use ir::InstructionArith::*;

    // All clear - execute normally
    if operands.iter().all(|v| !v.is_symbol()) {
        let clear_ops: Vec<Value> = operands
            .iter()
            .map(|v| v.as_clear().expect("all operands should be clear"))
            .collect();
        return match arithmetic::execute(op, clear_ops) {
            Ok(value) => FoldResult::Clear(value),
            Err(e) => FoldResult::Error(e),
        };
    }

    // Mixed - check for special cases
    match op {
        I32Mul | I64Mul => {
            for (i, v) in operands.iter().enumerate() {
                if let Ok(val) = v.as_clear() {
                    // x * 0 = 0
                    if val.is_zero() {
                        return FoldResult::Clear(val);
                    }
                    // x * 1 = x
                    if val.is_one() {
                        return FoldResult::Identity(1 - i);
                    }
                }
            }
        }
        I32Add | I64Add => {
            for (i, v) in operands.iter().enumerate() {
                if let Ok(val) = v.as_clear() {
                    // x + 0 = x
                    if val.is_zero() {
                        return FoldResult::Identity(1 - i);
                    }
                }
            }
        }
        I32Sub | I64Sub => {
            // x - 0 = x (subtrahend is 0)
            // operands[0] is top of stack (second WASM operand = subtrahend)
            if let Ok(val) = operands[0].as_clear() {
                if val.is_zero() {
                    return FoldResult::Identity(1); // keep operands[1] (minuend)
                }
            }
        }
        I32And | I64And => {
            for v in operands.iter() {
                if let Ok(val) = v.as_clear() {
                    // x & 0 = 0
                    if val.is_zero() {
                        return FoldResult::Clear(val);
                    }
                }
            }
        }
        I32Or | I64Or | I32Xor | I64Xor => {
            for (i, v) in operands.iter().enumerate() {
                if let Ok(val) = v.as_clear() {
                    // x | 0 = x, x ^ 0 = x
                    if val.is_zero() {
                        return FoldResult::Identity(1 - i);
                    }
                }
            }
        }
        _ => {}
    }

    FoldResult::None
}

/// Result of executing a call.
#[derive(Debug)]
pub enum RunResult {
    /// Execution completed with an optional result value.
    Complete {
        result: Option<Value>,
        ops: Option<SymbolicOps>,
    },
    /// Execution blocked on a host function.
    Blocked { ops: Option<SymbolicOps> },
}

/// Pending decode operation waiting for resolution.
#[derive(Debug)]
struct PendingDecode {
    id: usize,
    ty: ValType,
}

/// A call frame representing a function invocation.
#[derive(Debug)]
pub(crate) struct Frame {
    /// Original function index in the module.
    func_idx: u32,
    /// Function type.
    func_type: ir::FuncType,
    /// Local variable definitions.
    local_defs: Vec<ir::Local>,
    /// Local variables (parameters + locals).
    locals: Vec<IValue>,
    body: Arc<[Instruction]>,
    /// Current instruction pointer within this frame.
    ip: usize,
    /// Control flow label stack: (start_ip, end_ip, is_loop, stack_height,
    /// result_count).
    labels: Vec<(usize, usize, bool, usize, usize)>,
    /// Maps original local index -> trace local index (only for symbolic
    /// locals). Absent entries mean the local is clear (not in trace).
    local_to_trace: BTreeMap<u32, u32>,
    /// Next available trace local index.
    next_trace_local: u32,
}

impl Frame {
    /// Get or allocate a trace local index for the given original local index.
    fn get_or_insert_trace_local(&mut self, orig_idx: u32) -> u32 {
        *self.local_to_trace.entry(orig_idx).or_insert_with(|| {
            let idx = self.next_trace_local;
            self.next_trace_local += 1;
            idx
        })
    }
}

/// Execution context for a single top-level call.
///
/// Each independent call gets its own context with separate operand stack
/// and call stack. This allows calls to be preprocessed independently
/// while sharing memory and globals.
#[derive(Debug)]
pub struct Call {
    /// The operand stack.
    stack: OperandStack,
    /// The call stack (function frames).
    call_stack: Vec<Frame>,
    tracer: TraceBuilder,
    /// Whether execution has completed.
    done: bool,
    /// If true, automatically decode symbolic return values.
    decode_return: bool,
    /// The result type of the top-level function (for decode_return).
    result_type: Option<ValType>,
    /// Pending decode operation waiting for resolution.
    pending_decode: Option<PendingDecode>,
}

impl Call {
    /// Get a reference to the operand stack.
    pub fn stack(&self) -> &OperandStack {
        &self.stack
    }

    /// Get a mutable reference to the operand stack.
    pub fn stack_mut(&mut self) -> &mut OperandStack {
        &mut self.stack
    }

    /// Enable automatic decoding of symbolic return values.
    pub fn set_decode_return(&mut self) {
        self.decode_return = true;
    }

    /// Create a new call with pre-resolved function information.
    ///
    /// `func_id_base` should be `module.num_functions()` - folded function IDs
    /// start at this value to distinguish them from decode calls.
    pub fn new(func_idx: u32, func: &LocalFunction, args: Vec<IValue>) -> Self {
        let local_defs = func.locals().to_vec();
        let func_type = func.func_type().clone();

        // Initialize remaining locals to zero
        let mut locals = args;
        for local in &local_defs {
            let zero_value = match local.ty {
                ValType::I32 => IValue::from(0i32),
                ValType::I64 => IValue::from(0i64),
                ValType::F32 => IValue::from(0.0f32),
                ValType::F64 => IValue::from(0.0f64),
            };
            for _ in 0..local.count {
                locals.push(zero_value);
            }
        }

        // Build local-to-trace mapping for symbolic locals
        let mut local_to_trace = BTreeMap::new();
        let mut next_trace_local = 0u32;
        for (i, local) in locals.iter().enumerate() {
            if local.is_symbol() {
                local_to_trace.insert(i as u32, next_trace_local);
                next_trace_local += 1;
            }
        }

        let body_len = func.body().len();
        let result_count = func_type.results.len();
        let result_type = func_type.results.first().copied();

        let frame = Frame {
            func_idx,
            func_type,
            local_defs,
            locals,
            body: func.body().clone(),
            ip: 0,
            // Add implicit label for function body (br 0 at function level = return)
            // (start_ip, end_ip, is_loop, stack_height, result_count)
            labels: vec![(0, body_len, false, 0, result_count)],
            local_to_trace,
            next_trace_local,
        };

        Self {
            stack: OperandStack::new(),
            call_stack: vec![frame],
            tracer: TraceBuilder::default(),
            done: false,
            decode_return: false,
            result_type,
            pending_decode: None,
        }
    }

    /// Push a new frame for a function call.
    fn push_frame(&mut self, func_idx: u32, func: &LocalFunction) -> Result<(), VmError> {
        // Validate single-value return (multi-value not supported)
        if func.func_type().results.len() > 1 {
            return Err(VmError::Unsupported("multi-value return".into()));
        }

        // Pop arguments from stack
        let num_params = func.func_type().params.len();
        let mut args = Vec::with_capacity(num_params);
        for _ in 0..num_params {
            args.push(self.stack.pop()?);
        }
        args.reverse();

        // Initialize locals (params + local vars)
        let mut locals = args;
        let local_defs = func.locals().to_vec();
        for local in &local_defs {
            let zero_value = match local.ty {
                ValType::I32 => IValue::from(0i32),
                ValType::I64 => IValue::from(0i64),
                ValType::F32 => IValue::from(0.0f32),
                ValType::F64 => IValue::from(0.0f64),
            };
            for _ in 0..local.count {
                locals.push(zero_value);
            }
        }

        // Build local-to-trace mapping for symbolic locals
        let mut local_to_trace = BTreeMap::new();
        let mut next_trace_local = 0u32;
        for (i, local) in locals.iter().enumerate() {
            if local.is_symbol() {
                local_to_trace.insert(i as u32, next_trace_local);
                next_trace_local += 1;
            }
        }

        // Emit LocalSet to pop symbolic params from trace stack into trace locals.
        // Process in reverse order: last param is on top of trace stack.
        for i in (0..num_params).rev() {
            if locals[i].is_symbol() {
                let trace_idx = local_to_trace[&(i as u32)];
                self.tracer.push_instr(Instruction::LocalSet(trace_idx));
            }
        }

        let body_len = func.body().len();
        let func_type = func.func_type().clone();
        let result_count = func_type.results.len();

        let frame = Frame {
            func_idx,
            func_type,
            local_defs,
            locals,
            body: func.body().clone(),
            ip: 0,
            // Add implicit label for function body (br 0 at function level = return)
            // (start_ip, end_ip, is_loop, stack_height, result_count)
            labels: vec![(0, body_len, false, self.stack.len(), result_count)],
            local_to_trace,
            next_trace_local,
        };
        self.call_stack.push(frame);

        Ok(())
    }

    /// Execute until a decode is encountered or execution completes.
    ///
    /// Returns:
    /// - `Complete { result, ops }` when execution completes
    /// - `Blocked { ops }` when blocked on a decode operation
    ///
    /// The ops are returned for the caller to pass to the backend.
    pub(crate) fn run(
        &mut self,
        module: &Module,
        state: &mut State,
        host_state: &mut HostState,
    ) -> Result<RunResult, VmError> {
        // Check for pending decode resolution
        if let Some(pending) = self.pending_decode.take() {
            if let Some(value) = host_state.resolve_decode(pending.id) {
                let mut ops = SymbolicOps::new();
                ops.push(SymbolicOp::FnComplete);
                return Ok(RunResult::Complete {
                    result: Some(value),
                    ops: Some(ops),
                });
            } else {
                self.pending_decode = Some(pending);
                return Ok(RunResult::Blocked { ops: None });
            }
        }

        loop {
            let frame = self
                .call_stack
                .last()
                .ok_or_else(|| VmError::Internal("call already completed".into()))?;

            if frame.ip >= frame.body.len() {
                self.call_stack.pop();
                if self.call_stack.is_empty() {
                    return self.complete(host_state);
                }
                continue;
            }

            if self.step(module, state, host_state)?.is_pending() {
                let ops = self.tracer.build().map(|trace| {
                    let mut ops = SymbolicOps::new();
                    ops.push(SymbolicOp::Trace(trace));
                    ops
                });
                return Ok(RunResult::Blocked { ops });
            }

            if self.done {
                return self.complete(host_state);
            }
        }
    }

    /// Handle function completion - returns result and any pending ops.
    fn complete(&mut self, host_state: &mut HostState) -> Result<RunResult, VmError> {
        self.done = true;
        let mut ops = SymbolicOps::new();

        // Add any pending trace
        if let Some(trace) = self.tracer.build() {
            ops.push(SymbolicOp::Trace(trace));
        }

        // No result type -> complete with None
        let Some(result_type) = self.result_type else {
            ops.push(SymbolicOp::FnComplete);
            let ops = if ops.is_empty() { None } else { Some(ops) };
            return Ok(RunResult::Complete { result: None, ops });
        };

        let result = self.stack.pop()?;

        // Clear result -> complete immediately
        if let Ok(clear) = result.as_clear() {
            ops.push(SymbolicOp::FnComplete);
            let ops = if ops.is_empty() { None } else { Some(ops) };
            return Ok(RunResult::Complete {
                result: Some(clear),
                ops,
            });
        }

        // Symbolic result
        if !self.decode_return {
            return Err(VmError::SymbolicReturn);
        }

        // Auto-decode: add host fn op, register pending, block
        let decode_id = host_state.next_decode_id();
        let host_fn = match result_type {
            ValType::I32 => HostFnId::DecodeI32(decode_id),
            ValType::I64 => HostFnId::DecodeI64(decode_id),
            ValType::F32 => HostFnId::DecodeF32(decode_id),
            ValType::F64 => HostFnId::DecodeF64(decode_id),
        };
        ops.push(SymbolicOp::HostFn(host_fn));
        self.pending_decode = Some(PendingDecode {
            id: decode_id,
            ty: result_type,
        });

        let ops = if ops.is_empty() { None } else { Some(ops) };
        Ok(RunResult::Blocked { ops })
    }

    /// Execute a single instruction.
    fn step(
        &mut self,
        module: &Module,
        state: &mut State,
        host_state: &mut HostState,
    ) -> Result<Poll<()>, VmError> {
        let frame = self.call_stack.last().unwrap();
        let instr = frame.body[frame.ip].clone();

        match instr {
            // ===== Control flow =====
            Instruction::Unreachable => return Err(Trap::Unreachable.into()),
            Instruction::Nop => self.advance_ip(),

            Instruction::Block { blockty } => {
                let result_count = Self::block_result_count(module, &blockty);
                let stack_height = self.stack.len();
                let frame = self.call_stack.last_mut().unwrap();
                let end_ip = Self::find_matching_end(&frame.body, frame.ip)?;
                frame
                    .labels
                    .push((frame.ip + 1, end_ip + 1, false, stack_height, result_count));
                self.advance_ip();
            }

            Instruction::Loop { blockty } => {
                let result_count = Self::block_result_count(module, &blockty);
                let stack_height = self.stack.len();
                let frame = self.call_stack.last_mut().unwrap();
                let end_ip = Self::find_matching_end(&frame.body, frame.ip)?;
                frame
                    .labels
                    .push((frame.ip + 1, end_ip + 1, true, stack_height, result_count));
                self.advance_ip();
            }

            Instruction::If { blockty } => {
                let condition = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicConditional)?;

                let result_count = Self::block_result_count(module, &blockty);
                let stack_height = self.stack.len();
                let frame = self.call_stack.last_mut().unwrap();
                let (else_ip_opt, end_ip) = Self::find_if_branches(&frame.body, frame.ip)?;
                frame
                    .labels
                    .push((frame.ip + 1, end_ip + 1, false, stack_height, result_count));

                if condition == 0 {
                    if let Some(else_ip) = else_ip_opt {
                        frame.ip = else_ip + 1;
                    } else {
                        frame.ip = end_ip;
                    }
                } else {
                    frame.ip += 1;
                }
            }

            Instruction::Else => {
                let frame = self.call_stack.last_mut().unwrap();
                let end_ip = Self::find_matching_end_from_else(&frame.body, frame.ip)?;
                frame.ip = end_ip;
            }

            Instruction::End => {
                let frame = self.call_stack.last_mut().unwrap();
                if !frame.labels.is_empty() {
                    let (_, _, _, stack_height, result_count) = frame.labels.pop().unwrap();
                    // Clean up stack: keep only the result values
                    let mut results = Vec::with_capacity(result_count);
                    for _ in 0..result_count {
                        results.push(self.stack.pop()?);
                    }
                    // Count and remove discarded symbolic values from the trace
                    let mut symbolic_discarded = 0;
                    while self.stack.len() > stack_height {
                        let val = self.stack.pop()?;
                        if val.is_symbol() {
                            symbolic_discarded += 1;
                        }
                    }
                    if symbolic_discarded > 0 {
                        self.tracer.fold_to_const(symbolic_discarded);
                    }
                    for v in results.into_iter().rev() {
                        self.stack.push(v);
                    }
                }
                self.advance_ip();
            }

            Instruction::Br(depth) => {
                self.do_branch(depth)?;
            }

            Instruction::BrIf(depth) => {
                let condition = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicConditional)?;

                if condition != 0 {
                    self.do_branch(depth)?;
                } else {
                    self.advance_ip();
                }
            }

            Instruction::BrTable { targets, default } => {
                let index =
                    self.stack
                        .pop()?
                        .as_i32()?
                        .as_clear()
                        .map_err(|_| VmError::SymbolicConditional)? as usize;

                let depth = if index < targets.len() {
                    targets[index]
                } else {
                    default
                };
                self.do_branch(depth)?;
            }

            Instruction::Return => {
                // Return discards all values except the result value(s).
                // We need to remove any discarded symbolic values from the trace.
                let result_count = self.result_type.map(|_| 1).unwrap_or(0);

                // Pop result values
                let mut results = Vec::with_capacity(result_count);
                for _ in 0..result_count {
                    results.push(self.stack.pop()?);
                }

                // Count and remove discarded symbolic values from the trace
                let mut symbolic_discarded = 0;
                while !self.stack.is_empty() {
                    let val = self.stack.pop()?;
                    if val.is_symbol() {
                        symbolic_discarded += 1;
                    }
                }
                if symbolic_discarded > 0 {
                    self.tracer.fold_to_const(symbolic_discarded);
                }

                // Push results back
                for v in results.into_iter().rev() {
                    self.stack.push(v);
                }

                self.call_stack.clear();
                self.done = true;
            }

            // ===== Constants =====
            Instruction::I32Const(value) => {
                self.stack.push(IValue::from(value));
                self.advance_ip();
            }
            Instruction::I64Const(value) => {
                self.stack.push(IValue::from(value));
                self.advance_ip();
            }

            // ===== Local variables =====
            Instruction::LocalGet(local_idx) => {
                let frame = self.call_stack.last().unwrap();
                let value = frame
                    .locals
                    .get(local_idx as usize)
                    .copied()
                    .ok_or(VmError::UndefinedLocal(local_idx))?;

                if value.is_symbol() {
                    let trace_idx = frame.local_to_trace[&local_idx];
                    self.tracer.push_instr(Instruction::LocalGet(trace_idx));
                }

                self.stack.push(value);
                self.advance_ip();
            }
            Instruction::LocalSet(local_idx) => {
                let value = self.stack.pop()?;
                let frame = self.call_stack.last_mut().unwrap();
                if local_idx as usize >= frame.locals.len() {
                    return Err(VmError::UndefinedLocal(local_idx));
                }

                if value.is_symbol() {
                    let trace_idx = frame.get_or_insert_trace_local(local_idx);
                    self.tracer.push_instr(Instruction::LocalSet(trace_idx));
                }

                frame.locals[local_idx as usize] = value;
                self.advance_ip();
            }
            Instruction::LocalTee(local_idx) => {
                let value = *self.stack.last()?;
                let frame = self.call_stack.last_mut().unwrap();
                if local_idx as usize >= frame.locals.len() {
                    return Err(VmError::UndefinedLocal(local_idx));
                }

                if value.is_symbol() {
                    let trace_idx = frame.get_or_insert_trace_local(local_idx);
                    self.tracer.push_instr(Instruction::LocalTee(trace_idx));
                }

                frame.locals[local_idx as usize] = value;
                self.advance_ip();
            }

            // ===== Select =====
            Instruction::Select | Instruction::SelectTyped(_) => {
                let condition = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicConditional)?;
                let val2 = self.stack.pop()?;
                let val1 = self.stack.pop()?;

                let (result, discarded_is_symbolic) = if condition != 0 {
                    (val1, val2.is_symbol())
                } else {
                    (val2, val1.is_symbol())
                };

                // If the discarded value was symbolic, remove it from the trace
                if discarded_is_symbolic {
                    self.tracer.fold_to_const(1);
                }

                self.stack.push(result);
                self.advance_ip();
            }

            Instruction::Drop => {
                let val = self.stack.pop()?;
                if val.is_symbol() {
                    self.tracer.push_instr(Instruction::Drop);
                }
                self.advance_ip();
            }

            // ===== Global variables =====
            Instruction::GlobalGet(global_idx) => {
                let value = state
                    .globals()
                    .get(global_idx as usize)
                    .copied()
                    .ok_or(VmError::UndefinedGlobal(global_idx))?;

                self.stack.push(value);
                self.advance_ip();
            }
            Instruction::GlobalSet(global_idx) => {
                let value = self.stack.pop()?;
                let globals = state.globals_mut();
                if global_idx as usize >= globals.len() {
                    return Err(VmError::UndefinedGlobal(global_idx));
                }
                globals[global_idx as usize] = value;
                self.advance_ip();
            }

            // ===== Memory operations =====
            Instruction::I32Load(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 4);

                if mask == 0 {
                    // All clear
                    let bytes = memory.read_clear(addr, 4)?;
                    let val = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    self.stack.push(IValue::from(val));
                } else if mask == 0b1111 {
                    // All symbolic - emit base address with original memarg
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer.push_instr(instr);
                    self.stack.push(IValue::i32_symbol());
                } else {
                    // Mixed
                    emit_mixed_load_i32(&mut self.tracer, memory, addr, mask);
                    self.stack.push(IValue::i32_symbol());
                }
                self.advance_ip();
            }
            Instruction::I32Store(memarg) => {
                let value = self.stack.pop()?.as_i32()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &clear_val.to_le_bytes())?;
                } else {
                    memory.mark_symbol(addr, 4)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::I32Store(memarg.clone()));
                }
                self.advance_ip();
            }

            Instruction::I64Load(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 8);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 8)?;
                    let val = i64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    self.stack.push(IValue::from(val));
                } else if mask == 0b11111111 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer.push_instr(instr);
                    self.stack.push(IValue::i64_symbol());
                } else {
                    emit_mixed_load_i64(&mut self.tracer, memory, addr, mask);
                    self.stack.push(IValue::i64_symbol());
                }
                self.advance_ip();
            }

            Instruction::I64Store(memarg) => {
                let value = self.stack.pop()?.as_i64()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &clear_val.to_le_bytes())?;
                } else {
                    memory.mark_symbol(addr, 8)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Store(memarg.clone()));
                }
                self.advance_ip();
            }

            // Partial loads - sign/zero extend to i32
            Instruction::I32Load8S(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;

                if memory.is_symbol(addr) {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I32Load8S(memarg.clone()));
                    self.stack.push(IValue::i32_symbol());
                } else {
                    let bytes = memory.read_clear(addr, 1)?;
                    let val = bytes[0] as i8 as i32;
                    self.stack.push(IValue::from(val));
                }
                self.advance_ip();
            }

            Instruction::I32Load8U(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;

                if memory.is_symbol(addr) {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I32Load8U(memarg.clone()));
                    self.stack.push(IValue::i32_symbol());
                } else {
                    let bytes = memory.read_clear(addr, 1)?;
                    let val = bytes[0] as i32;
                    self.stack.push(IValue::from(val));
                }
                self.advance_ip();
            }

            Instruction::I32Load16S(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 2);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 2)?;
                    let val = i16::from_le_bytes([bytes[0], bytes[1]]) as i32;
                    self.stack.push(IValue::from(val));
                } else if mask == 0b11 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I32Load16S(memarg.clone()));
                    self.stack.push(IValue::i32_symbol());
                } else {
                    emit_mixed_load_i16s(&mut self.tracer, memory, addr, mask);
                    self.stack.push(IValue::i32_symbol());
                }
                self.advance_ip();
            }

            Instruction::I32Load16U(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 2);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 2)?;
                    let val = u16::from_le_bytes([bytes[0], bytes[1]]) as i32;
                    self.stack.push(IValue::from(val));
                } else if mask == 0b11 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I32Load16U(memarg.clone()));
                    self.stack.push(IValue::i32_symbol());
                } else {
                    emit_mixed_load_i16u(&mut self.tracer, memory, addr, mask);
                    self.stack.push(IValue::i32_symbol());
                }
                self.advance_ip();
            }

            // Partial loads - sign/zero extend to i64
            Instruction::I64Load8S(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;

                if memory.is_symbol(addr) {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Load8S(memarg.clone()));
                    self.stack.push(IValue::i64_symbol());
                } else {
                    let bytes = memory.read_clear(addr, 1)?;
                    let val = bytes[0] as i8 as i64;
                    self.stack.push(IValue::from(val));
                }
                self.advance_ip();
            }

            Instruction::I64Load8U(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;

                if memory.is_symbol(addr) {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Load8U(memarg.clone()));
                    self.stack.push(IValue::i64_symbol());
                } else {
                    let bytes = memory.read_clear(addr, 1)?;
                    let val = bytes[0] as i64;
                    self.stack.push(IValue::from(val));
                }
                self.advance_ip();
            }

            Instruction::I64Load16S(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 2);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 2)?;
                    let val = i16::from_le_bytes([bytes[0], bytes[1]]) as i64;
                    self.stack.push(IValue::from(val));
                } else if mask == 0b11 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Load16S(memarg.clone()));
                    self.stack.push(IValue::i64_symbol());
                } else {
                    emit_mixed_load_i16_to_i64s(&mut self.tracer, memory, addr, mask);
                    self.stack.push(IValue::i64_symbol());
                }
                self.advance_ip();
            }

            Instruction::I64Load16U(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 2);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 2)?;
                    let val = u16::from_le_bytes([bytes[0], bytes[1]]) as i64;
                    self.stack.push(IValue::from(val));
                } else if mask == 0b11 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Load16U(memarg.clone()));
                    self.stack.push(IValue::i64_symbol());
                } else {
                    emit_mixed_load_i16_to_i64u(&mut self.tracer, memory, addr, mask);
                    self.stack.push(IValue::i64_symbol());
                }
                self.advance_ip();
            }

            Instruction::I64Load32S(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 4);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 4)?;
                    let val = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64;
                    self.stack.push(IValue::from(val));
                } else if mask == 0b1111 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Load32S(memarg.clone()));
                    self.stack.push(IValue::i64_symbol());
                } else {
                    emit_mixed_load_i32_to_i64s(&mut self.tracer, memory, addr, mask);
                    self.stack.push(IValue::i64_symbol());
                }
                self.advance_ip();
            }

            Instruction::I64Load32U(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 4);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 4)?;
                    let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64;
                    self.stack.push(IValue::from(val));
                } else if mask == 0b1111 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Load32U(memarg.clone()));
                    self.stack.push(IValue::i64_symbol());
                } else {
                    emit_mixed_load_i32_to_i64u(&mut self.tracer, memory, addr, mask);
                    self.stack.push(IValue::i64_symbol());
                }
                self.advance_ip();
            }

            // Partial stores - truncate from i32/i64
            Instruction::I32Store8(memarg) => {
                let value = self.stack.pop()?.as_i32()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &[clear_val as u8])?;
                } else {
                    memory.mark_symbol(addr, 1)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::I32Store8(memarg.clone()));
                }
                self.advance_ip();
            }

            Instruction::I32Store16(memarg) => {
                let value = self.stack.pop()?.as_i32()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &(clear_val as u16).to_le_bytes())?;
                } else {
                    memory.mark_symbol(addr, 2)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::I32Store16(memarg.clone()));
                }
                self.advance_ip();
            }

            Instruction::I64Store8(memarg) => {
                let value = self.stack.pop()?.as_i64()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &[clear_val as u8])?;
                } else {
                    memory.mark_symbol(addr, 1)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Store8(memarg.clone()));
                }
                self.advance_ip();
            }

            Instruction::I64Store16(memarg) => {
                let value = self.stack.pop()?.as_i64()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &(clear_val as u16).to_le_bytes())?;
                } else {
                    memory.mark_symbol(addr, 2)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Store16(memarg.clone()));
                }
                self.advance_ip();
            }

            Instruction::I64Store32(memarg) => {
                let value = self.stack.pop()?.as_i64()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &(clear_val as u32).to_le_bytes())?;
                } else {
                    memory.mark_symbol(addr, 4)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::I64Store32(memarg.clone()));
                }
                self.advance_ip();
            }

            Instruction::MemorySize => {
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let pages = memory.size_pages();
                self.stack.push(IValue::from(pages as i32));
                self.advance_ip();
            }

            Instruction::MemoryGrow => {
                let delta = self.stack.pop()?.as_i32()?.as_clear()?;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                match memory.grow(delta as u32) {
                    Ok(prev_pages) => {
                        self.stack.push(IValue::from(prev_pages as i32));
                    }
                    Err(_) => {
                        // On failure, push -1
                        self.stack.push(IValue::from(-1i32));
                    }
                }
                self.advance_ip();
            }

            Instruction::MemoryFill => {
                // memory.fill: [dest, val, size] -> []
                let size = self.stack.pop()?.as_i32()?.as_clear()? as usize;
                let val = self.stack.pop()?.as_i32()?.as_clear()? as u8;
                let dest = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)? as usize;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                memory.fill(dest, val, size)?;
                self.advance_ip();
            }

            Instruction::MemoryCopy => {
                // memory.copy: [dest, src, size] -> []
                let size = self.stack.pop()?.as_i32()?.as_clear()? as usize;
                let src = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)? as usize;
                let dest = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)? as usize;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                memory.copy(dest, src, size)?;
                self.advance_ip();
            }

            Instruction::MemoryInit(data_idx) => {
                // memory.init: [dest, src_offset, size] -> []
                let size = self.stack.pop()?.as_i32()?.as_clear()? as usize;
                let src_offset = self.stack.pop()?.as_i32()?.as_clear()? as usize;
                let dest = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)? as usize;
                let data = module
                    .data()
                    .get(data_idx as usize)
                    .ok_or_else(|| VmError::Internal("invalid data segment".into()))?;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                let src_data = data
                    .data
                    .get(src_offset..src_offset + size)
                    .ok_or_else(|| VmError::Internal("data segment out of bounds".into()))?;
                memory.write(dest, src_data)?;
                self.advance_ip();
            }

            Instruction::DataDrop(_data_idx) => {
                todo!()
            }

            // ===== Call instructions =====
            Instruction::Call(func_idx) => {
                return self.do_call(module, host_state, func_idx, instr);
            }

            Instruction::CallIndirect {
                type_index,
                table_index: _,
            } => {
                // Pop table index - must be clear
                let idx = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicValue)?;

                // Bounds check and lookup
                let table = state.table();
                if idx < 0 || idx as usize >= table.len() {
                    return Err(Trap::UndefinedElement.into());
                }
                let func_idx = table[idx as usize].ok_or(Trap::UndefinedElement)?;

                // Type check
                let expected_type = &module.types()[type_index as usize];
                let func = module
                    .function(func_idx)
                    .ok_or(VmError::UndefinedFunction(func_idx))?;
                if func.func_type() != expected_type {
                    return Err(Trap::IndirectCallTypeMismatch.into());
                }

                if self
                    .do_call(module, host_state, func_idx, instr)?
                    .is_pending()
                {
                    // Push table index back so we can re-execute on resume
                    self.stack.push(idx.into());
                    return Ok(Poll::Pending);
                }
            }

            // ===== Arithmetic =====
            Instruction::Arith(ref arith_instr) => {
                let operand_count = arith_instr.input_arity();

                // Collect operands in stack order (top of stack first)
                // This matches the order expected by arithmetic::execute
                let mut operands: Vec<IValue> = Vec::with_capacity(operand_count);
                for i in 0..operand_count {
                    operands.push(*self.stack.peek(i)?);
                }

                match try_fold(arith_instr, &operands) {
                    FoldResult::Clear(value) => {
                        // Result is a constant value.
                        // If any operands are symbolic, we need to fold them out of the trace.
                        let symbolic_count = operands.iter().filter(|v| v.is_symbol()).count();
                        if symbolic_count > 0 {
                            self.tracer.fold_to_const(symbolic_count);
                        }
                        for _ in 0..operand_count {
                            self.stack.pop()?;
                        }
                        self.stack.push(value.into());
                    }
                    FoldResult::Identity(idx) => {
                        // Result is operand[idx] - the other operand is identity (0 or 1)
                        let result = operands[idx];
                        for _ in 0..operand_count {
                            self.stack.pop()?;
                        }
                        // Only fold if all non-identity operands are symbolic (in the trace).
                        // If they're clear, they're not in the trace and we can just push the
                        // result.
                        let non_identity_is_symbolic = operands
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| *i != idx)
                            .all(|(_, v)| v.is_symbol());
                        if non_identity_is_symbolic {
                            self.tracer.fold_identity(&instr, idx);
                        }
                        self.stack.push(result);
                    }
                    FoldResult::None => {
                        // Can't fold - emit const for clear operands, then instruction.
                        // operands[0] is top of stack, operands[n-1] is deepest.
                        // The trace stack must match wasm stack order: deeper operands first.
                        // Insert each clear operand at depth = count of symbolic operands above it.
                        for i in (0..operand_count).rev() {
                            let val = self.stack.peek(i)?;
                            if !val.is_symbol() {
                                // Count symbolic operands at indices < i (above this one in stack)
                                let depth = operands[..i].iter().filter(|v| v.is_symbol()).count();
                                self.tracer.insert_const(depth, val.as_clear()?);
                            }
                        }
                        self.tracer.push_instr(instr.clone());
                        for _ in 0..operand_count {
                            self.stack.pop()?;
                        }
                        self.stack.push(IValue::symbol(arith_instr.return_ty()));
                    }
                    FoldResult::Error(e) => {
                        return Err(e);
                    }
                }
                self.advance_ip();
            }

            // ===== Float constants =====
            Instruction::F32Const(bits) => {
                self.stack.push(f32::from_bits(bits).into());
                self.advance_ip();
            }
            Instruction::F64Const(bits) => {
                self.stack.push(f64::from_bits(bits).into());
                self.advance_ip();
            }

            // ===== Float loads =====
            Instruction::F32Load(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 4);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 4)?;
                    let val = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    self.stack.push(IValue::from(val));
                } else if mask == 0b1111 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer.push_instr(Instruction::F32Load(memarg.clone()));
                    self.stack.push(IValue::symbol(ValType::F32));
                } else {
                    // Mixed: build as i32 then reinterpret
                    emit_mixed_load_i32(&mut self.tracer, memory, addr, mask);
                    self.tracer
                        .push_instr(Instruction::Arith(ir::InstructionArith::F32ReinterpretI32));
                    self.stack.push(IValue::symbol(ValType::F32));
                }
                self.advance_ip();
            }
            Instruction::F64Load(memarg) => {
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory().ok_or(VmError::MemoryNotDefined)?;
                let mask = compute_symbol_mask(memory, addr, 8);

                if mask == 0 {
                    let bytes = memory.read_clear(addr, 8)?;
                    let val = f64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]);
                    self.stack.push(IValue::from(val));
                } else if mask == 0b11111111 {
                    self.tracer.push_instr(Instruction::I32Const(addr_val));
                    self.tracer.push_instr(Instruction::F64Load(memarg.clone()));
                    self.stack.push(IValue::symbol(ValType::F64));
                } else {
                    // Mixed: build as i64 then reinterpret
                    emit_mixed_load_i64(&mut self.tracer, memory, addr, mask);
                    self.tracer
                        .push_instr(Instruction::Arith(ir::InstructionArith::F64ReinterpretI64));
                    self.stack.push(IValue::symbol(ValType::F64));
                }
                self.advance_ip();
            }

            // ===== Float stores =====
            Instruction::F32Store(memarg) => {
                let value = self.stack.pop()?.as_f32()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &clear_val.to_le_bytes())?;
                } else {
                    memory.mark_symbol(addr, 4)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::F32Store(memarg.clone()));
                }
                self.advance_ip();
            }
            Instruction::F64Store(memarg) => {
                let value = self.stack.pop()?.as_f64()?;
                let addr_val = self
                    .stack
                    .pop()?
                    .as_i32()?
                    .as_clear()
                    .map_err(|_| VmError::SymbolicAddress)?;
                let addr = (addr_val as u64 + memarg.offset as u64) as u32;
                let memory = state.memory_mut().ok_or(VmError::MemoryNotDefined)?;

                if let Ok(clear_val) = value.as_clear() {
                    memory.write_clear(addr, &clear_val.to_le_bytes())?;
                } else {
                    memory.mark_symbol(addr, 8)?;
                    self.tracer.insert_const(1, Value::I32(addr_val));
                    self.tracer
                        .push_instr(Instruction::F64Store(memarg.clone()));
                }
                self.advance_ip();
            }

            // ===== Unimplemented =====
            _ => {
                return Err(VmError::Unsupported(format!(
                    "unimplemented instruction: {:?}",
                    instr
                )));
            }
        }

        Ok(Poll::Ready(()))
    }

    /// Advance the instruction pointer.
    pub fn advance_ip(&mut self) {
        if let Some(frame) = self.call_stack.last_mut() {
            frame.ip += 1;
        }
    }

    /// Execute a branch to the given label depth.
    fn do_branch(&mut self, depth: u32) -> Result<(), VmError> {
        let frame = self.call_stack.last_mut().unwrap();

        if (depth as usize) >= frame.labels.len() {
            return Err(VmError::Internal(format!(
                "invalid branch depth: {}",
                depth
            )));
        }

        let label_idx = frame.labels.len() - 1 - (depth as usize);
        let (start, target, is_loop, stack_height, result_count) = frame.labels[label_idx];

        // Save result values
        let mut results = Vec::with_capacity(result_count);
        for _ in 0..result_count {
            results.push(self.stack.pop()?);
        }

        // Count and remove discarded symbolic values from the trace
        let mut symbolic_discarded = 0;
        while self.stack.len() > stack_height {
            let val = self.stack.pop()?;
            if val.is_symbol() {
                symbolic_discarded += 1;
            }
        }

        // Remove discarded symbolic values from the trace
        if symbolic_discarded > 0 {
            self.tracer.fold_to_const(symbolic_discarded);
        }

        // Push results back
        for v in results.into_iter().rev() {
            self.stack.push(v);
        }

        if is_loop {
            // For loops, branch to the start
            frame.ip = start;
        } else {
            // For blocks, branch past the end
            // Pop labels up to and including target
            for _ in 0..=depth {
                frame.labels.pop();
            }
            frame.ip = target;
        }

        Ok(())
    }

    /// Execute a function call by index.
    fn do_call(
        &mut self,
        module: &Module,
        host_state: &mut HostState,
        func_idx: u32,
        instr: Instruction,
    ) -> Result<Poll<()>, VmError> {
        let func = module
            .function(func_idx)
            .ok_or(VmError::UndefinedFunction(func_idx))?;

        match func {
            Function::Import(func) => {
                // Collect args from stack
                let num_params = func.func_type().params.len();
                let mut args = Vec::with_capacity(num_params);
                for _ in 0..num_params {
                    args.push(self.stack.pop()?);
                }
                args.reverse();

                match (func.module(), func.name()) {
                    ("mpz", "decode_i32") => {
                        let id = host_state.register_decode(args[0]);
                        self.tracer.push_instr(instr);
                        self.stack.push(IValue::from(id as i32));
                    }
                    ("mpz", "decode_i64") => {
                        let id = host_state.register_decode(args[0]);
                        self.tracer.push_instr(instr);
                        self.stack.push(IValue::from(id as i32));
                    }
                    ("mpz", "decode_i32_wait") => {
                        let id = args[0].as_i32()?.as_clear()?;
                        if let Some(value) = host_state.resolve_decode(id as usize) {
                            if value.ty() != ValType::I32 {
                                return Err(VmError::Internal(
                                    "decoded value is wrong type".into(),
                                ));
                            }
                            self.stack.push(value.into());
                        } else {
                            // Push arg back - will be re-popped on resume
                            self.stack.push(args[0]);
                            return Ok(Poll::Pending);
                        }
                    }
                    ("mpz", "decode_i64_wait") => {
                        let id = args[0].as_i32()?.as_clear()?;
                        if let Some(value) = host_state.resolve_decode(id as usize) {
                            if value.ty() != ValType::I64 {
                                return Err(VmError::Internal(
                                    "decoded value is wrong type".into(),
                                ));
                            }
                            self.stack.push(value.into());
                        } else {
                            // Push arg back - will be re-popped on resume
                            self.stack.push(args[0]);
                            return Ok(Poll::Pending);
                        }
                    }
                    _ => {
                        return Err(VmError::UnsupportedImport {
                            module: func.module().to_string(),
                            name: func.name().to_string(),
                        });
                    }
                }
                self.advance_ip();
            }
            Function::Local(func) => {
                self.advance_ip();
                self.push_frame(func_idx, func)?;
            }
        }
        Ok(Poll::Ready(()))
    }

    // ========== Control flow helpers ==========

    /// Get the number of result values for a block type.
    fn block_result_count(module: &Module, blockty: &ir::BlockType) -> usize {
        match blockty {
            ir::BlockType::Empty => 0,
            ir::BlockType::Type(_) => 1,
            ir::BlockType::FuncType(idx) => {
                // Look up the type in the module's type section
                module
                    .types()
                    .get(*idx as usize)
                    .map(|ft| ft.results.len())
                    .unwrap_or(0)
            }
        }
    }

    fn find_matching_end(instructions: &[Instruction], start_ip: usize) -> Result<usize, VmError> {
        let mut depth = 0;
        for (i, instr) in instructions.iter().enumerate().skip(start_ip + 1) {
            match instr {
                Instruction::Block { .. } | Instruction::Loop { .. } | Instruction::If { .. } => {
                    depth += 1;
                }
                Instruction::End => {
                    if depth == 0 {
                        return Ok(i);
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        Err(VmError::Internal(
            "unmatched control flow instruction".to_string(),
        ))
    }

    fn find_if_branches(
        instructions: &[Instruction],
        if_ip: usize,
    ) -> Result<(Option<usize>, usize), VmError> {
        let mut depth = 0;
        let mut else_ip = None;

        for (i, instr) in instructions.iter().enumerate().skip(if_ip + 1) {
            match instr {
                Instruction::Block { .. } | Instruction::Loop { .. } | Instruction::If { .. } => {
                    depth += 1;
                }
                Instruction::Else => {
                    if depth == 0 && else_ip.is_none() {
                        else_ip = Some(i);
                    }
                }
                Instruction::End => {
                    if depth == 0 {
                        return Ok((else_ip, i));
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        Err(VmError::Internal("unmatched if instruction".to_string()))
    }

    fn find_matching_end_from_else(
        instructions: &[Instruction],
        else_ip: usize,
    ) -> Result<usize, VmError> {
        let mut depth = 0;
        for (i, instr) in instructions.iter().enumerate().skip(else_ip + 1) {
            match instr {
                Instruction::Block { .. } | Instruction::Loop { .. } | Instruction::If { .. } => {
                    depth += 1;
                }
                Instruction::End => {
                    if depth == 0 {
                        return Ok(i);
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        Err(VmError::Internal("unmatched else instruction".to_string()))
    }
}

/// Compute a bitmask indicating which bytes in a range are symbolic.
/// Bit i is 1 if byte at addr+i is symbolic.
fn compute_symbol_mask(memory: &crate::Memory, addr: u32, len: usize) -> u8 {
    let mut mask = 0u8;
    for i in 0..len.min(8) {
        if memory.is_symbol(addr + i as u32) {
            mask |= 1 << i;
        }
    }
    mask
}

/// Get the raw bytes from memory at the given address.
/// Returns the underlying bytes regardless of symbolic status.
fn get_clear_bytes(memory: &crate::Memory, addr: u32, len: usize) -> Vec<u8> {
    let slice = memory.as_slice();
    let start = addr as usize;
    let end = (start + len).min(slice.len());
    slice[start..end].to_vec()
}

/// Emit trace instructions to reconstruct an i32 from mixed symbolic/concrete
/// bytes. Uses byte-level loads for symbolic bytes and constants for concrete
/// bytes, then combines with shifts and ORs.
fn emit_mixed_load_i32(tracer: &mut TraceBuilder, memory: &crate::Memory, addr: u32, mask: u8) {
    let bytes = get_clear_bytes(memory, addr, 4);
    let mut first = true;

    for i in 0..4u32 {
        let is_symbolic = (mask & (1 << i)) != 0;
        let shift = i * 8;

        if is_symbolic {
            // Emit: I32Const(addr + i), I32Load8U, (shift if needed)
            tracer.push_instr(Instruction::I32Const((addr + i) as i32));
            tracer.push_instr(Instruction::I32Load8U(ir::MemArg {
                align: 0,
                offset: 0,
            }));
            if shift > 0 {
                tracer.push_instr(Instruction::I32Const(shift as i32));
                tracer.push_instr(Instruction::Arith(ir::InstructionArith::I32Shl));
            }
        } else {
            // Emit constant with byte shifted to position
            let shifted = (bytes[i as usize] as i32) << shift;
            tracer.push_instr(Instruction::I32Const(shifted));
        }

        if !first {
            tracer.push_instr(Instruction::Arith(ir::InstructionArith::I32Or));
        }
        first = false;
    }
}

/// Emit trace instructions to reconstruct an i64 from mixed symbolic/concrete
/// bytes.
fn emit_mixed_load_i64(tracer: &mut TraceBuilder, memory: &crate::Memory, addr: u32, mask: u8) {
    let bytes = get_clear_bytes(memory, addr, 8);
    let mut first = true;

    for i in 0..8u32 {
        let is_symbolic = (mask & (1 << i)) != 0;
        let shift = i * 8;

        if is_symbolic {
            tracer.push_instr(Instruction::I32Const((addr + i) as i32));
            tracer.push_instr(Instruction::I64Load8U(ir::MemArg {
                align: 0,
                offset: 0,
            }));
            if shift > 0 {
                tracer.push_instr(Instruction::I64Const(shift as i64));
                tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64Shl));
            }
        } else {
            let shifted = (bytes[i as usize] as i64) << shift;
            tracer.push_instr(Instruction::I64Const(shifted));
        }

        if !first {
            tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64Or));
        }
        first = false;
    }
}

/// Emit trace for a 2-byte mixed load, returning i32 (zero-extended).
fn emit_mixed_load_i16u(tracer: &mut TraceBuilder, memory: &crate::Memory, addr: u32, mask: u8) {
    let bytes = get_clear_bytes(memory, addr, 2);
    let mut first = true;

    for i in 0..2u32 {
        let is_symbolic = (mask & (1 << i)) != 0;
        let shift = i * 8;

        if is_symbolic {
            tracer.push_instr(Instruction::I32Const((addr + i) as i32));
            tracer.push_instr(Instruction::I32Load8U(ir::MemArg {
                align: 0,
                offset: 0,
            }));
            if shift > 0 {
                tracer.push_instr(Instruction::I32Const(shift as i32));
                tracer.push_instr(Instruction::Arith(ir::InstructionArith::I32Shl));
            }
        } else {
            let shifted = (bytes[i as usize] as i32) << shift;
            tracer.push_instr(Instruction::I32Const(shifted));
        }

        if !first {
            tracer.push_instr(Instruction::Arith(ir::InstructionArith::I32Or));
        }
        first = false;
    }
}

/// Emit trace for a 2-byte mixed load with sign extension to i32.
fn emit_mixed_load_i16s(tracer: &mut TraceBuilder, memory: &crate::Memory, addr: u32, mask: u8) {
    // Build unsigned 16-bit value first
    emit_mixed_load_i16u(tracer, memory, addr, mask);
    // Sign extend: (val << 16) >> 16 (arithmetic shift)
    tracer.push_instr(Instruction::I32Const(16));
    tracer.push_instr(Instruction::Arith(ir::InstructionArith::I32Shl));
    tracer.push_instr(Instruction::I32Const(16));
    tracer.push_instr(Instruction::Arith(ir::InstructionArith::I32ShrS));
}

/// Emit trace for a 4-byte mixed load returning i64 (zero-extended).
fn emit_mixed_load_i32_to_i64u(
    tracer: &mut TraceBuilder,
    memory: &crate::Memory,
    addr: u32,
    mask: u8,
) {
    let bytes = get_clear_bytes(memory, addr, 4);
    let mut first = true;

    for i in 0..4u32 {
        let is_symbolic = (mask & (1 << i)) != 0;
        let shift = i * 8;

        if is_symbolic {
            tracer.push_instr(Instruction::I32Const((addr + i) as i32));
            tracer.push_instr(Instruction::I64Load8U(ir::MemArg {
                align: 0,
                offset: 0,
            }));
            if shift > 0 {
                tracer.push_instr(Instruction::I64Const(shift as i64));
                tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64Shl));
            }
        } else {
            let shifted = (bytes[i as usize] as i64) << shift;
            tracer.push_instr(Instruction::I64Const(shifted));
        }

        if !first {
            tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64Or));
        }
        first = false;
    }
}

/// Emit trace for a 4-byte mixed load with sign extension to i64.
fn emit_mixed_load_i32_to_i64s(
    tracer: &mut TraceBuilder,
    memory: &crate::Memory,
    addr: u32,
    mask: u8,
) {
    emit_mixed_load_i32_to_i64u(tracer, memory, addr, mask);
    // Sign extend: (val << 32) >> 32 (arithmetic shift)
    tracer.push_instr(Instruction::I64Const(32));
    tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64Shl));
    tracer.push_instr(Instruction::I64Const(32));
    tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64ShrS));
}

/// Emit trace for a 2-byte mixed load returning i64 (zero-extended).
fn emit_mixed_load_i16_to_i64u(
    tracer: &mut TraceBuilder,
    memory: &crate::Memory,
    addr: u32,
    mask: u8,
) {
    let bytes = get_clear_bytes(memory, addr, 2);
    let mut first = true;

    for i in 0..2u32 {
        let is_symbolic = (mask & (1 << i)) != 0;
        let shift = i * 8;

        if is_symbolic {
            tracer.push_instr(Instruction::I32Const((addr + i) as i32));
            tracer.push_instr(Instruction::I64Load8U(ir::MemArg {
                align: 0,
                offset: 0,
            }));
            if shift > 0 {
                tracer.push_instr(Instruction::I64Const(shift as i64));
                tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64Shl));
            }
        } else {
            let shifted = (bytes[i as usize] as i64) << shift;
            tracer.push_instr(Instruction::I64Const(shifted));
        }

        if !first {
            tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64Or));
        }
        first = false;
    }
}

/// Emit trace for a 2-byte mixed load with sign extension to i64.
fn emit_mixed_load_i16_to_i64s(
    tracer: &mut TraceBuilder,
    memory: &crate::Memory,
    addr: u32,
    mask: u8,
) {
    emit_mixed_load_i16_to_i64u(tracer, memory, addr, mask);
    // Sign extend from 16 bits
    tracer.push_instr(Instruction::I64Const(48));
    tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64Shl));
    tracer.push_instr(Instruction::I64Const(48));
    tracer.push_instr(Instruction::Arith(ir::InstructionArith::I64ShrS));
}
