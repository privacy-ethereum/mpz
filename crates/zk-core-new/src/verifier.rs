pub(crate) mod arithmetic;

use std::collections::{BTreeMap, VecDeque};

use mpz_common::{Context, future::MaybeDone};
use mpz_core::Block;
use mpz_memory_core::correlated::{Delta, Key};
use mpz_ot::rcot::{RCOTSender, RCOTSenderOutput};
use mpz_vm_core_new::{
    CallContext, Memory, Module, Param, PauseOn, ResolvedFunc, State, VmError, Yield,
    value::{SymbolId, IValue, Value, ValueState},
};
use serio::stream::IoStreamExt;

use crate::{I32Key, I64Key, Triple};

/// Encoded value storage for the verifier (Keys).
#[derive(Debug, Clone)]
pub(crate) enum EncodedValue {
    I32(I32Key),
    I64(I64Key),
}

/// A call waiting to start execution.
struct PendingCall {
    call: CallContext,
    encoded: BTreeMap<SymbolId, EncodedValue>,
    /// IDs which we're waiting to receive keys for.
    pending: Vec<SymbolId>,
}

/// A currently executing call.
struct ActiveCall {
    call: CallContext,
    /// Per-call encoded value storage (Keys).
    encoded: BTreeMap<SymbolId, EncodedValue>,
    /// Recorded triples for the consistency check.
    triples: Vec<Triple<Key>>,
    /// Adjustment bits received from the prover.
    adjust_bits: Vec<bool>,
}

/// ZK Verifier VM.
///
/// The verifier holds the keys for encoded values. During execution,
/// encoded arithmetic is performed on the keys. Triples are recorded for
/// the consistency check.
pub struct Verifier<RCOT> {
    state: State,
    encoding_id: SymbolId,
    rcot: RCOT,
    delta: Delta,
    /// Blind values queued to receive keys for.
    pending_blind: Vec<ir::ValType>,
    /// Keys received from OT for authenticated values.
    received_keys: VecDeque<EncodedValue>,
    /// Calls waiting to start.
    pending_calls: VecDeque<PendingCall>,
    /// Currently executing call.
    active_call: Option<ActiveCall>,
    /// All recorded triples for the consistency check.
    all_triples: Vec<Triple<Key>>,
    /// All adjustment bits for the transcript.
    all_adjust: Vec<bool>,
    /// Pre-allocated mask Keys for AND gates.
    mask_pool: VecDeque<Key>,
    /// Adjustment bits received from prover for AND gates.
    pending_adjust_bits: VecDeque<bool>,
    /// Encoded values stored in globals.
    encoded_globals: BTreeMap<SymbolId, EncodedValue>,
    /// Encoded memory (stores Keys).
    encoded_memory: Option<Memory>,
}

impl<RCOT> Verifier<RCOT>
where
    RCOT: RCOTSender<Block>,
{
    /// Creates a new verifier VM.
    pub fn new(module: Module, rcot: RCOT) -> Result<Self, VmError> {
        let delta = Delta::new(rcot.delta());
        let state = State::new(module)?;
        let memory = state.memory().cloned();
        Ok(Self {
            state,
            encoding_id: SymbolId::default(),
            rcot,
            delta,
            pending_blind: Vec::new(),
            received_keys: VecDeque::new(),
            pending_calls: VecDeque::new(),
            active_call: None,
            all_triples: Vec::new(),
            all_adjust: Vec::new(),
            mask_pool: VecDeque::new(),
            pending_adjust_bits: VecDeque::new(),
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
                Param::Blind(ty) => {
                    let id = self.encoding_id.next();
                    let val = match ty {
                        ir::ValType::I32 => IValue::I32(ValueState::Symbol(id)),
                        ir::ValType::I64 => IValue::I64(ValueState::Symbol(id)),
                        ir::ValType::F32 | ir::ValType::F64 => {
                            return Err(VmError::Unsupported(
                                "floating point parameters not supported".to_string(),
                            ));
                        }
                    };
                    self.pending_blind.push(ty);
                    pending.push(id);
                    vals.push(val);
                }
                Param::Private(_) => {
                    // Verifier cannot have private values - that's for the prover
                    return Err(VmError::Unsupported(
                        "verifier cannot use private values".to_string(),
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
        // Get keys for pending blind values via OT
        if !self.pending_blind.is_empty() {
            let count: usize = self
                .pending_blind
                .iter()
                .map(|ty| match ty {
                    ir::ValType::I32 => 32,
                    ir::ValType::I64 => 64,
                    _ => 0,
                })
                .sum();

            // Send keys via OT
            let RCOTSenderOutput { keys, .. } = self
                .rcot
                .try_send_rcot(count)
                .map_err(|e| VmError::Internal(format!("OT error: {:?}", e)))?;

            let mut raw_keys: Vec<Key> = keys.into_iter().map(Key::from).collect();

            // Receive adjustment bits from prover
            let adjust_bits: Vec<bool> = ctx
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| VmError::Internal(format!("IO error: {:?}", e)))?;

            if adjust_bits.len() != count {
                return Err(VmError::Internal(format!(
                    "expected {} adjustment bits, got {}",
                    count,
                    adjust_bits.len()
                )));
            }

            // Apply adjustment to keys: key ^= adjust ? delta : 0
            for (key, &adjust) in raw_keys.iter_mut().zip(adjust_bits.iter()) {
                key.adjust(adjust, &self.delta);
            }

            let mut key_idx = 0;
            for ty in std::mem::take(&mut self.pending_blind) {
                match ty {
                    ir::ValType::I32 => {
                        let mut i32_key = I32Key::default();
                        for i in 0..32 {
                            i32_key.0[i] = raw_keys[key_idx + i];
                        }
                        key_idx += 32;
                        self.received_keys.push_back(EncodedValue::I32(i32_key));
                    }
                    ir::ValType::I64 => {
                        let mut i64_key = I64Key::default();
                        for i in 0..64 {
                            i64_key.0[i] = raw_keys[key_idx + i];
                        }
                        key_idx += 64;
                        self.received_keys.push_back(EncodedValue::I64(i64_key));
                    }
                    _ => {}
                }
            }
        }

        // Drive execution
        self.drive()?;

        // Receive adjustment bits for AND gates from prover
        if self.active_call.is_some() && self.pending_adjust_bits.is_empty() {
            if let Ok(adjust_bits) = ctx.io_mut().expect_next::<Vec<bool>>().await {
                self.pending_adjust_bits.extend(adjust_bits);
            }
        }

        Ok(())
    }

    /// Drive execution as far as possible.
    fn drive(&mut self) -> Result<(), VmError> {
        loop {
            if let Some(ref mut active) = self.active_call {
                match active.call.run(&mut self.state, None)? {
                    Yield::Done => {
                        self.all_triples.append(&mut active.triples);
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
                if self.received_keys.len() >= pending.pending.len() {
                    let PendingCall {
                        call,
                        mut encoded,
                        pending,
                    } = self.pending_calls.pop_front().unwrap();

                    for id in pending {
                        encoded.insert(id, self.received_keys.pop_front().unwrap());
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

    /// Execute encoded arithmetic on Keys.
    fn execute_encoded_arith(&mut self, instr: &ir::InstructionArith) -> Result<(), VmError> {
        // Pop operands first
        let mut stack_values = Vec::with_capacity(instr.input_arity());
        {
            let active = self.active_call.as_mut().unwrap();
            for _ in 0..instr.input_arity() {
                stack_values.push(active.call.stack_mut().pop()?);
            }
        }

        // Now get keys without conflicting borrows
        let mut operands = Vec::with_capacity(stack_values.len());
        let active = self.active_call.as_ref().unwrap();
        for operand in &stack_values {
            let key = self.get_key(operand, &active.encoded)?;
            operands.push(key);
        }
        drop(active);

        // Execute the arithmetic (TODO: implement proper Key arithmetic)
        let result = match instr {
            ir::InstructionArith::I32Add => {
                // For now, just XOR the Keys (placeholder)
                let a = match &operands[1] {
                    EncodedValue::I32(k) => k,
                    _ => return Err(VmError::Internal("expected i32".into())),
                };
                let b = match &operands[0] {
                    EncodedValue::I32(k) => k,
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

    /// Get Key from a stack value.
    fn get_key(
        &self,
        stack_val: &IValue,
        encoded: &BTreeMap<SymbolId, EncodedValue>,
    ) -> Result<EncodedValue, VmError> {
        match stack_val {
            IValue::I32(ValueState::Clear(v)) => {
                // Convert clear value to Key with public keys
                let mut key = I32Key::default();
                for i in 0..32 {
                    let bit = (*v >> i) & 1 == 1;
                    key.0[i] = Key::public(bit, &self.delta);
                }
                Ok(EncodedValue::I32(key))
            }
            IValue::I32(ValueState::Symbol(id)) => encoded
                .get(id)
                .cloned()
                .ok_or_else(|| VmError::Internal("encoded value not found".into())),
            IValue::I64(ValueState::Clear(v)) => {
                let mut key = I64Key::default();
                for i in 0..64 {
                    let bit = (*v >> i) & 1 == 1;
                    key.0[i] = Key::public(bit, &self.delta);
                }
                Ok(EncodedValue::I64(key))
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
                        let key = active
                            .encoded
                            .remove(&id)
                            .ok_or_else(|| VmError::Internal("encoded value not found".into()))?;
                        match key {
                            EncodedValue::I32(k) => {
                                // Verifier doesn't have the actual value - use pointer bits
                                let mut val: i32 = 0;
                                for (i, key) in k.0.iter().enumerate() {
                                    if key.pointer() {
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
                        let key = active
                            .encoded
                            .remove(&id)
                            .ok_or_else(|| VmError::Internal("encoded value not found".into()))?;
                        match key {
                            EncodedValue::I64(k) => {
                                let mut val: i64 = 0;
                                for (i, key) in k.0.iter().enumerate() {
                                    if key.pointer() {
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
        active.call.stack_mut().pop()?;

        let id = self.encoding_id.next();
        let key = I32Key::default(); // Placeholder

        let active = self.active_call.as_mut().unwrap();
        active.encoded.insert(id, EncodedValue::I32(key));
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
        active.call.stack_mut().pop()?;

        let id = stack_val
            .encoded_id()
            .ok_or_else(|| VmError::Internal("expected encoded value".into()))?;

        let _value = active
            .encoded
            .remove(&id)
            .ok_or_else(|| VmError::Internal("encoded value not found".into()))?;

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
        let key = I64Key::default();

        let active = self.active_call.as_mut().unwrap();
        active.encoded.insert(id, EncodedValue::I64(key));
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
