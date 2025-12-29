pub(crate) mod arithmetic;

use std::collections::{BTreeMap, VecDeque};

use mpz_common::{Context, future::MaybeDone};
use mpz_core::Block;
use mpz_memory_core::correlated::Mac;
use mpz_ot::rcot::{RCOTReceiver, RCOTReceiverOutput};
use mpz_vm_core_new::{
    CallContext, Memory, Module, Param, PauseOn, ResolvedFunc, State, VmError, Yield,
    value::{IValue, SymbolId, Value, ValueState},
};
use serio::SinkExt;

use crate::{I32Mac, I64Mac, Triple};

/// Encoded value storage for the prover (MACs).
#[derive(Debug, Clone)]
pub(crate) enum EncodedValue {
    I32(I32Mac),
    I64(I64Mac),
}

/// A call waiting to start execution.
struct PendingCall {
    call: CallContext,
    encoded: BTreeMap<SymbolId, EncodedValue>,
    /// IDs which we're waiting to receive MACs for.
    pending: Vec<SymbolId>,
}

/// A currently executing call.
struct ActiveCall {
    call: CallContext,
    /// Per-call encoded value storage (MACs).
    encoded: BTreeMap<SymbolId, EncodedValue>,
    /// Recorded triples for the consistency check.
    triples: Vec<Triple<Mac>>,
    /// Adjustment bits to send to the verifier.
    adjust_bits: Vec<bool>,
}

/// ZK Prover VM.
///
/// The prover holds the private values and their MACs. During execution,
/// encoded arithmetic is performed on the MACs. Triples are recorded for
/// the consistency check.
pub struct Prover<RCOT> {
    state: State,
    encoding_id: SymbolId,
    rcot: RCOT,
    /// Private values queued to authenticate and send MACs for.
    pending_private: Vec<Value>,
    /// MACs received from OT for authenticated values.
    received_macs: VecDeque<EncodedValue>,
    /// Calls waiting to start (need blind values).
    pending_calls: VecDeque<PendingCall>,
    /// Currently executing call.
    active_call: Option<ActiveCall>,
    /// All recorded triples for the consistency check.
    all_triples: Vec<Triple<Mac>>,
    /// All adjustment bits for the transcript.
    all_adjust: Vec<bool>,
    /// Pre-allocated mask MACs for AND gates.
    mask_pool: VecDeque<Mac>,
    /// Encoded values stored in globals.
    encoded_globals: BTreeMap<SymbolId, EncodedValue>,
    /// Encoded memory (stores MACs).
    encoded_memory: Option<Memory>,
}

impl<RCOT> Prover<RCOT>
where
    RCOT: RCOTReceiver<bool, Block>,
{
    /// Creates a new prover VM.
    pub fn new(module: Module, rcot: RCOT) -> Result<Self, VmError> {
        let state = State::new(module)?;
        let memory = state.memory().cloned();
        Ok(Self {
            state,
            encoding_id: SymbolId::default(),
            rcot,
            pending_private: Vec::new(),
            received_macs: VecDeque::new(),
            pending_calls: VecDeque::new(),
            active_call: None,
            all_triples: Vec::new(),
            all_adjust: Vec::new(),
            mask_pool: VecDeque::new(),
            encoded_globals: BTreeMap::new(),
            encoded_memory: memory,
        })
    }

    /// Queue a function call for execution.
    pub fn call(
        &mut self,
        func_idx: u32,
        args: Vec<Param>,
    ) -> Result<MaybeDone<Option<Value>>, VmError> {
        let mut encoded = BTreeMap::new();
        let mut pending = Vec::new();
        let mut vals = Vec::new();

        for arg in args {
            match arg {
                Param::Private(v) => {
                    let id = self.encoding_id.next();
                    let val = match v.ty() {
                        ir::ValType::I32 => IValue::I32(ValueState::Symbol(id)),
                        ir::ValType::I64 => IValue::I64(ValueState::Symbol(id)),
                        ir::ValType::F32 | ir::ValType::F64 => {
                            return Err(VmError::Unsupported(
                                "floating point parameters not supported".to_string(),
                            ));
                        }
                    };
                    // Queue the value for OT authentication
                    self.pending_private.push(v);
                    pending.push(id);
                    vals.push(val);
                }
                Param::Blind(_) => {
                    // Prover cannot have blind values - that's for the verifier
                    return Err(VmError::Unsupported(
                        "prover cannot use blind values".to_string(),
                    ));
                }
                Param::Public(v) => vals.push(IValue::from(v)),
            }
        }

        let func = self.state.call(func_idx, &vals)?;
        let (call, output) = CallContext::new(func_idx, func, vals);

        self.pending_calls.push_back(PendingCall {
            call,
            encoded,
            pending,
        });

        Ok(output)
    }

    /// Exchange values and execute queued calls.
    pub async fn flush(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        // Get MACs for pending private values via OT
        if !self.pending_private.is_empty() {
            let count: usize = self
                .pending_private
                .iter()
                .map(|v| match v {
                    Value::I32(_) => 32,
                    Value::I64(_) => 64,
                })
                .sum();

            // Receive MACs from OT
            let RCOTReceiverOutput { msgs, choices, .. } = self
                .rcot
                .try_recv_rcot(count)
                .map_err(|e| VmError::Internal(format!("OT error: {:?}", e)))?;

            let macs: Vec<Mac> = msgs.into_iter().map(Mac::from).collect();

            // Compute adjustment bits: adjust = value XOR choice
            let mut adjust_bits = Vec::with_capacity(count);
            let mut mac_idx = 0;

            for value in std::mem::take(&mut self.pending_private) {
                match value {
                    Value::I32(v) => {
                        let mut i32_mac = I32Mac::default();
                        for i in 0..32 {
                            let bit = (v >> i) & 1 == 1;
                            let choice = choices[mac_idx + i];
                            adjust_bits.push(bit ^ choice);
                            let mut mac = macs[mac_idx + i];
                            mac.set_pointer(bit);
                            i32_mac.0[i] = mac;
                        }
                        mac_idx += 32;
                        self.received_macs.push_back(EncodedValue::I32(i32_mac));
                    }
                    Value::I64(v) => {
                        let mut i64_mac = I64Mac::default();
                        for i in 0..64 {
                            let bit = (v >> i) & 1 == 1;
                            let choice = choices[mac_idx + i];
                            adjust_bits.push(bit ^ choice);
                            let mut mac = macs[mac_idx + i];
                            mac.set_pointer(bit);
                            i64_mac.0[i] = mac;
                        }
                        mac_idx += 64;
                        self.received_macs.push_back(EncodedValue::I64(i64_mac));
                    }
                }
            }

            // Send adjustment bits to the verifier
            ctx.io_mut()
                .send(adjust_bits)
                .await
                .map_err(|e| VmError::Internal(format!("IO error: {:?}", e)))?;
        }

        // Drive execution
        self.drive()?;

        // Send adjustment bits from AND gates to verifier
        if let Some(ref mut active) = self.active_call {
            if !active.adjust_bits.is_empty() {
                let adjust_bits = std::mem::take(&mut active.adjust_bits);
                ctx.io_mut()
                    .send(adjust_bits)
                    .await
                    .map_err(|e| VmError::Internal(format!("IO error: {:?}", e)))?;
            }
        }

        Ok(())
    }

    /// Drive execution as far as possible.
    fn drive(&mut self) -> Result<(), VmError> {
        loop {
            // Try to make progress on active call
            if let Some(ref mut active) = self.active_call {
                match active.call.run(&mut self.state, None)? {
                    Yield::Done => {
                        // Move triples to the global list for consistency check
                        self.all_triples.append(&mut active.triples);
                        self.all_adjust.append(&mut active.adjust_bits);
                        self.active_call = None;
                    }
                    Yield::EncodedArith { instr } => {
                        self.execute_encoded_arith(&instr)?;
                        continue;
                    }
                    Yield::Import { resolved } => {
                        self.handle_import(&resolved)?;
                        continue;
                    }
                    Yield::GlobalGetEncoded { global_idx } => {
                        self.handle_global_get_encoded(global_idx)?;
                        continue;
                    }
                    Yield::GlobalSetEncoded { global_idx } => {
                        self.handle_global_set_encoded(global_idx)?;
                        continue;
                    }
                    Yield::I32LoadEncoded { addr } => {
                        self.handle_i32_load_encoded(addr)?;
                        continue;
                    }
                    Yield::I32StoreEncoded { addr } => {
                        self.handle_i32_store_encoded(addr)?;
                        continue;
                    }
                    Yield::I64LoadEncoded { addr } => {
                        self.handle_i64_load_encoded(addr)?;
                        continue;
                    }
                    Yield::I64StoreEncoded { addr } => {
                        self.handle_i64_store_encoded(addr)?;
                        continue;
                    }
                    Yield::MemoryGrow { delta_pages } => {
                        self.handle_memory_grow(delta_pages)?;
                        continue;
                    }
                    _ => continue,
                }
            }

            // Try to start a pending call
            if let Some(pending) = self.pending_calls.front() {
                if self.received_macs.len() >= pending.pending.len() {
                    let PendingCall {
                        call,
                        mut encoded,
                        pending,
                    } = self.pending_calls.pop_front().unwrap();

                    for id in pending {
                        encoded.insert(id, self.received_macs.pop_front().unwrap());
                    }

                    self.active_call = Some(ActiveCall {
                        call,
                        encoded,
                        triples: Vec::new(),
                        adjust_bits: Vec::new(),
                    });
                    continue;
                }
            }

            break;
        }

        Ok(())
    }

    /// Execute encoded arithmetic on MACs.
    fn execute_encoded_arith(&mut self, instr: &ir::InstructionArith) -> Result<(), VmError> {
        // Pop operands first
        let mut stack_values = Vec::with_capacity(instr.input_arity());
        {
            let active = self.active_call.as_mut().unwrap();
            for _ in 0..instr.input_arity() {
                stack_values.push(active.call.stack_mut().pop()?);
            }
        }

        // Now get macs without conflicting borrows
        let mut operands = Vec::with_capacity(stack_values.len());
        let active = self.active_call.as_ref().unwrap();
        for operand in &stack_values {
            let mac = self.get_mac(operand, &active.encoded)?;
            operands.push(mac);
        }
        drop(active);

        // Execute the arithmetic (TODO: implement proper MAC arithmetic)
        let result = match instr {
            ir::InstructionArith::I32Add => {
                // For now, just XOR the MACs (placeholder)
                let a = match &operands[1] {
                    EncodedValue::I32(m) => m,
                    _ => return Err(VmError::Internal("expected i32".into())),
                };
                let b = match &operands[0] {
                    EncodedValue::I32(m) => m,
                    _ => return Err(VmError::Internal("expected i32".into())),
                };
                EncodedValue::I32(*a ^ *b) // Placeholder - real add needs ripple carry
            }
            _ => {
                return Err(VmError::Unsupported(format!(
                    "unsupported encoded arithmetic: {:?}",
                    instr
                )));
            }
        };

        // Store result with new ID
        let id = self.encoding_id.next();
        let active = self.active_call.as_mut().unwrap();
        let result_stack = match &result {
            EncodedValue::I32(_) => IValue::I32(ValueState::Symbol(id)),
            EncodedValue::I64(_) => IValue::I64(ValueState::Symbol(id)),
        };
        active.encoded.insert(id, result);
        active.call.stack_mut().push(result_stack);
        active.call.advance_ip();

        Ok(())
    }

    /// Get MAC from a stack value.
    fn get_mac(
        &self,
        stack_val: &IValue,
        encoded: &BTreeMap<SymbolId, EncodedValue>,
    ) -> Result<EncodedValue, VmError> {
        match stack_val {
            IValue::I32(ValueState::Clear(v)) => {
                // Convert clear value to MAC with public MACs
                let mut mac = I32Mac::default();
                for i in 0..32 {
                    let bit = (*v >> i) & 1 == 1;
                    mac.0[i] = Mac::PUBLIC[bit as usize];
                }
                Ok(EncodedValue::I32(mac))
            }
            IValue::I32(ValueState::Symbol(id)) => encoded
                .get(id)
                .cloned()
                .ok_or_else(|| VmError::Internal("encoded value not found".into())),
            IValue::I64(ValueState::Clear(v)) => {
                let mut mac = I64Mac::default();
                for i in 0..64 {
                    let bit = (*v >> i) & 1 == 1;
                    mac.0[i] = Mac::PUBLIC[bit as usize];
                }
                Ok(EncodedValue::I64(mac))
            }
            IValue::I64(ValueState::Symbol(id)) => encoded
                .get(id)
                .cloned()
                .ok_or_else(|| VmError::Internal("encoded value not found".into())),
        }
    }

    /// Handle an import call.
    fn handle_import(&mut self, resolved: &ResolvedFunc) -> Result<(), VmError> {
        let active = self.active_call.as_mut().unwrap();
        let module = resolved.import_module.as_deref().unwrap_or("");
        let name = resolved.import_name.as_deref().unwrap_or("");

        match (module, name) {
            ("mpz", "decode_i32") => {
                let stack_val = active.call.stack_mut().pop()?;
                let clear = match stack_val {
                    IValue::I32(ValueState::Clear(v)) => v,
                    IValue::I32(ValueState::Symbol(id)) => {
                        let mac = active
                            .encoded
                            .remove(&id)
                            .ok_or_else(|| VmError::Internal("encoded value not found".into()))?;
                        match mac {
                            EncodedValue::I32(m) => {
                                let mut val: i32 = 0;
                                for (i, mac) in m.0.iter().enumerate() {
                                    if mac.pointer() {
                                        val |= 1 << i;
                                    }
                                }
                                val
                            }
                            _ => return Err(VmError::Internal("type mismatch".into())),
                        }
                    }
                    _ => {
                        return Err(VmError::TypeMismatch {
                            expected: ir::ValType::I32,
                            got: stack_val.ty(),
                        });
                    }
                };
                active
                    .call
                    .stack_mut()
                    .push(IValue::I32(ValueState::Clear(clear)));
            }
            ("mpz", "decode_i64") => {
                let stack_val = active.call.stack_mut().pop()?;
                let clear = match stack_val {
                    IValue::I64(ValueState::Clear(v)) => v,
                    IValue::I64(ValueState::Symbol(id)) => {
                        let mac = active
                            .encoded
                            .remove(&id)
                            .ok_or_else(|| VmError::Internal("encoded value not found".into()))?;
                        match mac {
                            EncodedValue::I64(m) => {
                                let mut val: i64 = 0;
                                for (i, mac) in m.0.iter().enumerate() {
                                    if mac.pointer() {
                                        val |= 1 << i;
                                    }
                                }
                                val
                            }
                            _ => return Err(VmError::Internal("type mismatch".into())),
                        }
                    }
                    _ => {
                        return Err(VmError::TypeMismatch {
                            expected: ir::ValType::I64,
                            got: stack_val.ty(),
                        });
                    }
                };
                active
                    .call
                    .stack_mut()
                    .push(IValue::I64(ValueState::Clear(clear)));
            }
            _ => {
                return Err(VmError::Unsupported(format!(
                    "unknown import: {}::{}",
                    module, name
                )));
            }
        }

        active.call.advance_ip();
        Ok(())
    }

    fn handle_global_get_encoded(&mut self, global_idx: u32) -> Result<(), VmError> {
        let global_val = self
            .state
            .globals()
            .get(global_idx as usize)
            .copied()
            .ok_or(VmError::UndefinedGlobal(global_idx))?;

        let id = global_val
            .encoded_id()
            .ok_or_else(|| VmError::Internal("expected encoded global".into()))?;

        let value = self
            .encoded_globals
            .get(&id)
            .cloned()
            .ok_or_else(|| VmError::Internal("encoded global not found".into()))?;

        let active = self.active_call.as_mut().unwrap();
        active.encoded.insert(id, value);
        active.call.stack_mut().push(global_val);
        active.call.advance_ip();

        Ok(())
    }

    fn handle_global_set_encoded(&mut self, global_idx: u32) -> Result<(), VmError> {
        let active = self.active_call.as_mut().unwrap();
        let stack_val = active.call.stack_mut().pop()?;
        let id = stack_val
            .encoded_id()
            .ok_or_else(|| VmError::Internal("expected encoded value".into()))?;

        let value = active
            .encoded
            .remove(&id)
            .ok_or_else(|| VmError::Internal("encoded value not found".into()))?;

        self.encoded_globals.insert(id, value);

        let globals = self.state.globals_mut();
        if global_idx as usize >= globals.len() {
            return Err(VmError::UndefinedGlobal(global_idx));
        }
        globals[global_idx as usize] = stack_val;

        let active = self.active_call.as_mut().unwrap();
        active.call.advance_ip();

        Ok(())
    }

    fn handle_i32_load_encoded(&mut self, addr: u32) -> Result<(), VmError> {
        let active = self.active_call.as_mut().unwrap();
        active.call.stack_mut().pop()?; // Pop address

        // Read MACs from encoded memory (placeholder - would need MAC storage)
        let id = self.encoding_id.next();
        let mac = I32Mac::default(); // Placeholder

        let active = self.active_call.as_mut().unwrap();
        active.encoded.insert(id, EncodedValue::I32(mac));
        active
            .call
            .stack_mut()
            .push(IValue::I32(ValueState::Symbol(id)));
        active.call.advance_ip();

        Ok(())
    }

    fn handle_i32_store_encoded(&mut self, addr: u32) -> Result<(), VmError> {
        let active = self.active_call.as_mut().unwrap();
        let stack_val = active.call.stack_mut().pop()?;
        active.call.stack_mut().pop()?; // Pop address

        let id = stack_val
            .encoded_id()
            .ok_or_else(|| VmError::Internal("expected encoded value".into()))?;

        let _value = active
            .encoded
            .remove(&id)
            .ok_or_else(|| VmError::Internal("encoded value not found".into()))?;

        // Write MACs to encoded memory (placeholder)
        let state_mem = self.state.memory_mut().ok_or(VmError::MemoryNotDefined)?;
        state_mem.mark_encoded(addr, 4)?;

        let active = self.active_call.as_mut().unwrap();
        active.call.advance_ip();

        Ok(())
    }

    fn handle_i64_load_encoded(&mut self, addr: u32) -> Result<(), VmError> {
        let active = self.active_call.as_mut().unwrap();
        active.call.stack_mut().pop()?;

        let id = self.encoding_id.next();
        let mac = I64Mac::default();

        let active = self.active_call.as_mut().unwrap();
        active.encoded.insert(id, EncodedValue::I64(mac));
        active
            .call
            .stack_mut()
            .push(IValue::I64(ValueState::Symbol(id)));
        active.call.advance_ip();

        Ok(())
    }

    fn handle_i64_store_encoded(&mut self, addr: u32) -> Result<(), VmError> {
        let active = self.active_call.as_mut().unwrap();
        let stack_val = active.call.stack_mut().pop()?;
        active.call.stack_mut().pop()?;

        let id = stack_val
            .encoded_id()
            .ok_or_else(|| VmError::Internal("expected encoded value".into()))?;

        let _value = active
            .encoded
            .remove(&id)
            .ok_or_else(|| VmError::Internal("encoded value not found".into()))?;

        let state_mem = self.state.memory_mut().ok_or(VmError::MemoryNotDefined)?;
        state_mem.mark_encoded(addr, 8)?;

        let active = self.active_call.as_mut().unwrap();
        active.call.advance_ip();

        Ok(())
    }

    fn handle_memory_grow(&mut self, delta_pages: u32) -> Result<(), VmError> {
        let active = self.active_call.as_mut().unwrap();
        active.call.stack_mut().pop()?;

        let state_mem = self.state.memory_mut().ok_or(VmError::MemoryNotDefined)?;
        let result = state_mem.grow(delta_pages);

        if let Ok(prev_pages) = result {
            if let Some(ref mut encoded_mem) = self.encoded_memory {
                encoded_mem.grow(delta_pages)?;
            }
            active
                .call
                .stack_mut()
                .push(IValue::from(prev_pages as i32));
        } else {
            active.call.stack_mut().push(IValue::from(-1i32));
        }

        active.call.advance_ip();
        Ok(())
    }
}
