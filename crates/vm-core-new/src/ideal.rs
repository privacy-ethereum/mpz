//! Ideal backend for symbolic execution.
//!
//! This backend emulates an ideal MPC protocol by storing symbolic values
//! locally in the clear and exchanging private values during execution.

use std::collections::BTreeMap;

use ir::{Instruction, ValType};
use mpz_common::Context;
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};

use crate::{
    Backend, HostState, Instance, Trace, VmError, arithmetic,
    ops::{HostFnId, SymbolicOp, SymbolicOps},
    trace::TraceInput,
    value::Value,
};

/// Type alias for an ideal VM instance.
pub type IdealVm = Instance<IdealBackend>;

/// Values exchanged for a single call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CallInputs {
    /// The actual values (extracted from Private inputs).
    values: Vec<Value>,
}

/// Message exchanged during flush.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FlushMsg {
    /// Inputs per call, keyed by call_id.
    inputs: BTreeMap<usize, CallInputs>,
}

/// Byte-addressable memory for symbolic execution.
///
/// Stores symbolic bytes separately from the VM's clear memory.
/// Load operations merge bytes from both sources based on which
/// bytes are marked symbolic in the VM state.
#[derive(Debug, Default)]
struct IdealMemory {
    /// Symbolic bytes: addr -> byte value
    data: BTreeMap<u32, u8>,
}

impl IdealMemory {
    // === I32 operations ===

    /// Load i32 from memory, merging symbolic and clear bytes.
    fn i32_load(&self, addr: u32) -> Result<i32, VmError> {
        let bytes = self.load_bytes(addr, 4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Store i32 to symbolic memory.
    fn i32_store(&mut self, addr: u32, val: i32) {
        self.store_bytes(addr, &val.to_le_bytes());
    }

    /// Load 1 byte and sign-extend to i32.
    fn i32_load8_s(&self, addr: u32) -> Result<i32, VmError> {
        let bytes = self.load_bytes(addr, 1)?;
        Ok(bytes[0] as i8 as i32)
    }

    /// Load 1 byte and zero-extend to i32.
    fn i32_load8_u(&self, addr: u32) -> Result<i32, VmError> {
        let bytes = self.load_bytes(addr, 1)?;
        Ok(bytes[0] as i32)
    }

    /// Load 2 bytes and sign-extend to i32.
    fn i32_load16_s(&self, addr: u32) -> Result<i32, VmError> {
        let bytes = self.load_bytes(addr, 2)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]) as i32)
    }

    /// Load 2 bytes and zero-extend to i32.
    fn i32_load16_u(&self, addr: u32) -> Result<i32, VmError> {
        let bytes = self.load_bytes(addr, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]) as i32)
    }

    /// Store low 8 bits of i32.
    fn i32_store8(&mut self, addr: u32, val: i32) {
        self.store_bytes(addr, &[val as u8]);
    }

    /// Store low 16 bits of i32.
    fn i32_store16(&mut self, addr: u32, val: i32) {
        self.store_bytes(addr, &(val as u16).to_le_bytes());
    }

    // === I64 operations ===

    /// Load i64 from memory, merging symbolic and clear bytes.
    fn i64_load(&self, addr: u32) -> Result<i64, VmError> {
        let bytes = self.load_bytes(addr, 8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Store i64 to symbolic memory.
    fn i64_store(&mut self, addr: u32, val: i64) {
        self.store_bytes(addr, &val.to_le_bytes());
    }

    /// Load 1 byte and sign-extend to i64.
    fn i64_load8_s(&self, addr: u32) -> Result<i64, VmError> {
        let bytes = self.load_bytes(addr, 1)?;
        Ok(bytes[0] as i8 as i64)
    }

    /// Load 1 byte and zero-extend to i64.
    fn i64_load8_u(&self, addr: u32) -> Result<i64, VmError> {
        let bytes = self.load_bytes(addr, 1)?;
        Ok(bytes[0] as i64)
    }

    /// Load 2 bytes and sign-extend to i64.
    fn i64_load16_s(&self, addr: u32) -> Result<i64, VmError> {
        let bytes = self.load_bytes(addr, 2)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]) as i64)
    }

    /// Load 2 bytes and zero-extend to i64.
    fn i64_load16_u(&self, addr: u32) -> Result<i64, VmError> {
        let bytes = self.load_bytes(addr, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]) as i64)
    }

    /// Load 4 bytes and sign-extend to i64.
    fn i64_load32_s(&self, addr: u32) -> Result<i64, VmError> {
        let bytes = self.load_bytes(addr, 4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64)
    }

    /// Load 4 bytes and zero-extend to i64.
    fn i64_load32_u(&self, addr: u32) -> Result<i64, VmError> {
        let bytes = self.load_bytes(addr, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64)
    }

    /// Store low 8 bits of i64.
    fn i64_store8(&mut self, addr: u32, val: i64) {
        self.store_bytes(addr, &[val as u8]);
    }

    /// Store low 16 bits of i64.
    fn i64_store16(&mut self, addr: u32, val: i64) {
        self.store_bytes(addr, &(val as u16).to_le_bytes());
    }

    /// Store low 32 bits of i64.
    fn i64_store32(&mut self, addr: u32, val: i64) {
        self.store_bytes(addr, &(val as u32).to_le_bytes());
    }

    // === F32/F64 operations ===

    /// Load f32 from memory.
    fn f32_load(&self, addr: u32) -> Result<f32, VmError> {
        let bytes = self.load_bytes(addr, 4)?;
        Ok(f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Store f32 to symbolic memory.
    fn f32_store(&mut self, addr: u32, val: f32) {
        self.store_bytes(addr, &val.to_le_bytes());
    }

    /// Load f64 from memory.
    fn f64_load(&self, addr: u32) -> Result<f64, VmError> {
        let bytes = self.load_bytes(addr, 8)?;
        Ok(f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Store f64 to symbolic memory.
    fn f64_store(&mut self, addr: u32, val: f64) {
        self.store_bytes(addr, &val.to_le_bytes());
    }

    // === Internal helpers ===

    /// Load bytes from IdealMemory.
    ///
    /// Returns 0 for bytes that weren't stored during trace execution.
    /// Clear bytes are embedded in the trace via coalescing instructions,
    /// so we don't need to read from state memory here.
    fn load_bytes(&self, addr: u32, len: usize) -> Result<Vec<u8>, VmError> {
        let mut bytes = Vec::with_capacity(len);
        for i in 0..len {
            let byte_addr = addr + i as u32;
            // Return 0 for uninitialized bytes (clear bytes are embedded in trace)
            let byte = self.data.get(&byte_addr).copied().unwrap_or(0);
            bytes.push(byte);
        }
        Ok(bytes)
    }

    /// Store bytes to symbolic memory.
    fn store_bytes(&mut self, addr: u32, bytes: &[u8]) {
        for (i, &byte) in bytes.iter().enumerate() {
            self.data.insert(addr + i as u32, byte);
        }
    }
}

/// Ideal backend that stores symbolic values in clear.
///
/// This emulates an ideal MPC protocol by storing symbolic values locally
/// and exchanging private values during flush.
#[derive(Debug, Default)]
pub struct IdealBackend {
    memory: IdealMemory,
    /// Inputs per call, keyed by call_id: (Private values, Blind types).
    call_inputs: BTreeMap<usize, Vec<TraceInput>>,
    /// Inputs received from peer, keyed by call_id.
    received_inputs: BTreeMap<usize, CallInputs>,
    /// Pending ops waiting for execution: (call_id, ops)
    pending_ops: Vec<(usize, SymbolicOps)>,
    /// Next global decode id.
    next_decode_id: usize,
}

impl IdealBackend {
    /// Creates a new backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Execute symbolic operations for a call.
    fn execute_ops(
        &mut self,
        host_state: &mut HostState,
        module: &ir::Module,
        ops: &SymbolicOps,
        stack: &mut Vec<Value>,
        locals: &mut Vec<Value>,
    ) -> Result<(), VmError> {
        for op in ops.ops() {
            match op {
                SymbolicOp::Trace(trace) => {
                    self.execute_trace(stack, locals, module, host_state, trace)?;
                }
                SymbolicOp::HostFn(host_fn) => {
                    let value = stack
                        .pop()
                        .ok_or_else(|| VmError::Internal("stack underflow on decode".into()))?;
                    let decode_id = match host_fn {
                        HostFnId::DecodeI32(id)
                        | HostFnId::DecodeI64(id)
                        | HostFnId::DecodeF32(id)
                        | HostFnId::DecodeF64(id) => *id,
                    };
                    host_state.set_decode(decode_id, value);
                }
                SymbolicOp::FnComplete => {
                    if !stack.is_empty() {
                        return Err(VmError::Internal(format!(
                            "stack not empty on FnComplete: {} values remain",
                            stack.len()
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Execute a trace as a simple stack machine.
    fn execute_trace(
        &mut self,
        stack: &mut Vec<Value>,
        locals: &mut Vec<Value>,
        module: &ir::Module,
        host_state: &mut HostState,
        trace: &Trace,
    ) -> Result<(), VmError> {
        for instr in trace.instructions() {
            match instr {
                Instruction::I32Const(v) => stack.push(Value::I32(*v)),
                Instruction::I64Const(v) => stack.push(Value::I64(*v)),
                Instruction::F32Const(bits) => stack.push(Value::F32(f32::from_bits(*bits))),
                Instruction::F64Const(bits) => stack.push(Value::F64(f64::from_bits(*bits))),

                Instruction::LocalGet(idx) => {
                    let val = locals
                        .get(*idx as usize)
                        .copied()
                        .ok_or_else(|| VmError::Internal(format!("local {} not found", idx)))?;
                    stack.push(val);
                }
                Instruction::LocalSet(idx) => {
                    let val = stack
                        .pop()
                        .ok_or_else(|| VmError::Internal("stack underflow on LocalSet".into()))?;
                    while locals.len() <= *idx as usize {
                        locals.push(Value::I32(0));
                    }
                    locals[*idx as usize] = val;
                }
                Instruction::LocalTee(idx) => {
                    let val = *stack
                        .last()
                        .ok_or_else(|| VmError::Internal("stack underflow on LocalTee".into()))?;
                    while locals.len() <= *idx as usize {
                        locals.push(Value::I32(0));
                    }
                    locals[*idx as usize] = val;
                }

                Instruction::Drop => {
                    stack.pop();
                }

                Instruction::Select | Instruction::SelectTyped(_) => {
                    let cond = stack
                        .pop()
                        .ok_or_else(|| VmError::Internal("stack underflow on Select".into()))?
                        .as_i32()
                        .expect("condition should be i32");
                    let val2 = stack
                        .pop()
                        .ok_or_else(|| VmError::Internal("stack underflow on Select".into()))?;
                    let val1 = stack
                        .pop()
                        .ok_or_else(|| VmError::Internal("stack underflow on Select".into()))?;
                    stack.push(if cond != 0 { val1 } else { val2 });
                }

                Instruction::Arith(op) => {
                    let operands = pop_n(stack, op.input_arity());
                    let result = arithmetic::execute(op, operands)?;
                    stack.push(result);
                }

                Instruction::Return => {
                    break;
                }

                // === I32 memory operations ===
                Instruction::I32Load(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    let val = self.memory.i32_load(addr)?;
                    stack.push(Value::I32(val));
                }
                Instruction::I32Store(memarg) => {
                    let val = stack.pop().expect("value").as_i32().expect("i32 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.i32_store(addr, val);
                }
                Instruction::I32Load8S(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I32(self.memory.i32_load8_s(addr)?));
                }
                Instruction::I32Load8U(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    let val = self.memory.i32_load8_u(addr)?;
                    stack.push(Value::I32(val));
                }
                Instruction::I32Load16S(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I32(self.memory.i32_load16_s(addr)?));
                }
                Instruction::I32Load16U(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I32(self.memory.i32_load16_u(addr)?));
                }
                Instruction::I32Store8(memarg) => {
                    let val = stack.pop().expect("value").as_i32().expect("i32 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.i32_store8(addr, val);
                }
                Instruction::I32Store16(memarg) => {
                    let val = stack.pop().expect("value").as_i32().expect("i32 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.i32_store16(addr, val);
                }

                // === I64 memory operations ===
                Instruction::I64Load(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I64(self.memory.i64_load(addr)?));
                }
                Instruction::I64Store(memarg) => {
                    let val = stack.pop().expect("value").as_i64().expect("i64 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.i64_store(addr, val);
                }
                Instruction::I64Load8S(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I64(self.memory.i64_load8_s(addr)?));
                }
                Instruction::I64Load8U(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I64(self.memory.i64_load8_u(addr)?));
                }
                Instruction::I64Load16S(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I64(self.memory.i64_load16_s(addr)?));
                }
                Instruction::I64Load16U(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I64(self.memory.i64_load16_u(addr)?));
                }
                Instruction::I64Load32S(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I64(self.memory.i64_load32_s(addr)?));
                }
                Instruction::I64Load32U(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::I64(self.memory.i64_load32_u(addr)?));
                }
                Instruction::I64Store8(memarg) => {
                    let val = stack.pop().expect("value").as_i64().expect("i64 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.i64_store8(addr, val);
                }
                Instruction::I64Store16(memarg) => {
                    let val = stack.pop().expect("value").as_i64().expect("i64 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.i64_store16(addr, val);
                }
                Instruction::I64Store32(memarg) => {
                    let val = stack.pop().expect("value").as_i64().expect("i64 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.i64_store32(addr, val);
                }

                // === Float memory operations ===
                Instruction::F32Load(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::F32(self.memory.f32_load(addr)?));
                }
                Instruction::F32Store(memarg) => {
                    let val = stack.pop().expect("value").as_f32().expect("f32 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.f32_store(addr, val);
                }
                Instruction::F64Load(memarg) => {
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    stack.push(Value::F64(self.memory.f64_load(addr)?));
                }
                Instruction::F64Store(memarg) => {
                    let val = stack.pop().expect("value").as_f64().expect("f64 value");
                    let addr = stack.pop().expect("address").as_i32().expect("i32 addr");
                    let addr = (addr as u64 + memarg.offset as u64) as u32;
                    self.memory.f64_store(addr, val);
                }

                Instruction::Call(func_idx) => {
                    let func = module
                        .function(*func_idx)
                        .ok_or(VmError::UndefinedFunction(*func_idx))?;

                    match func {
                        ir::Function::Import(import) => {
                            match (import.module(), import.name()) {
                                ("mpz", "decode_i32") | ("mpz", "decode_i64") => {
                                    let value = stack.pop().ok_or_else(|| {
                                        VmError::Internal("stack underflow on decode Call".into())
                                    })?;
                                    let decode_id = self.next_decode_id;
                                    self.next_decode_id += 1;
                                    host_state.set_decode(decode_id, value);
                                    stack.push(Value::I32(decode_id as i32));
                                }
                                _ => {
                                    return Err(VmError::UnsupportedImport {
                                        module: import.module().to_string(),
                                        name: import.name().to_string(),
                                    });
                                }
                            }
                        }
                        ir::Function::Local(_) => {
                            return Err(VmError::Internal(
                                "local function calls should not appear in trace".into(),
                            ));
                        }
                    }
                }

                _ => {
                    return Err(VmError::Unsupported(format!(
                        "unsupported instruction in trace: {:?}",
                        instr
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Pop n values from the stack in reverse order (for correct operand order).
fn pop_n(stack: &mut Vec<Value>, n: usize) -> Vec<Value> {
    let mut result = Vec::with_capacity(n);
    for _ in 0..n {
        result.push(stack.pop().expect("stack should have value"));
    }
    result
}

impl Backend for IdealBackend {
    fn push_private(&mut self, call_id: usize, value: Value) -> Result<(), VmError> {
        self.call_inputs
            .entry(call_id)
            .or_default()
            .push(TraceInput::Private(value));
        Ok(())
    }

    fn push_blind(&mut self, call_id: usize, ty: ValType) -> Result<(), VmError> {
        self.call_inputs
            .entry(call_id)
            .or_default()
            .push(TraceInput::Blind(ty));
        Ok(())
    }

    fn push_ops(&mut self, call_id: usize, ops: SymbolicOps) {
        self.pending_ops.push((call_id, ops));
    }

    fn has_pending_ops(&self) -> bool {
        !self.pending_ops.is_empty()
    }

    async fn execute(
        &mut self,
        ctx: &mut Context,
        module: &ir::Module,
        host_state: &mut HostState,
    ) -> Result<(), VmError> {
        // 1. Extract Private values from call_inputs to send
        let mut to_send: BTreeMap<usize, CallInputs> = BTreeMap::new();
        for (call_id, inputs) in &self.call_inputs {
            let values: Vec<Value> = inputs
                .iter()
                .filter_map(|input| match input {
                    TraceInput::Private(v) => Some(*v),
                    TraceInput::Blind(_) => None,
                })
                .collect();
            to_send.insert(*call_id, CallInputs { values });
        }

        // 2. Exchange with peer
        ctx.io_mut()
            .send(FlushMsg { inputs: to_send })
            .await
            .map_err(|e| VmError::Internal(format!("send error: {}", e)))?;

        let received: FlushMsg = ctx
            .io_mut()
            .expect_next()
            .await
            .map_err(|e| VmError::Internal(format!("recv error: {}", e)))?;

        self.received_inputs = received.inputs;

        // 3. Execute all pending ops
        for (call_id, ops) in std::mem::take(&mut self.pending_ops) {
            // Resolve inputs for this call
            let inputs = self.call_inputs.remove(&call_id).unwrap_or_default();
            let received = self.received_inputs.remove(&call_id).unwrap_or_default();
            let mut received_iter = received.values.into_iter();

            let mut locals: Vec<Value> = Vec::new();
            for input in inputs {
                match input {
                    TraceInput::Private(v) => locals.push(v),
                    TraceInput::Blind(_ty) => {
                        locals.push(
                            received_iter
                                .next()
                                .ok_or_else(|| VmError::Internal("missing blind input".into()))?,
                        );
                    }
                }
            }

            let mut stack: Vec<Value> = Vec::new();
            self.execute_ops(host_state, module, &ops, &mut stack, &mut locals)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
