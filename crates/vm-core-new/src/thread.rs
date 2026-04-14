use crate::bitset::BitSet;
use ir::{
    BlockId, Function, FunctionBody, ImportedFunction, Instruction, InstructionArith,
    LocalFunction, Reg, Terminator,
};

use ir::Module;

use crate::{
    Directive, Global, Op, Operand, Trap, VmError, arithmetic,
    call::{Call, Param},
    memory::Memory,
    value::Value,
};

/// Thread context — passed to Thread::step and Thread::call.
pub struct Context<'a> {
    pub module: &'a Module,
    pub global: &'a mut Global,
}

/// Result of Thread::step().
#[derive(Debug)]
pub enum StepResult {
    /// Concrete instruction executed, keep stepping.
    Continue,
    /// A directive was emitted.
    Directive(Directive),
    /// Execution completed.
    Done { result: Option<Value> },
}

/// Result of a single instruction step (internal).
#[derive(Debug)]
enum FrameStepResult {
    Continue,
    Directive(Directive),
    Call {
        func_idx: u32,
        args: Vec<Operand>,
        dst: Option<Reg>,
    },
    Return {
        return_reg: Option<Reg>,
    },
}

/// Exit condition for an active private control flow region.
#[derive(Debug, Clone, Copy)]
enum PrivateCfExit {
    /// Exit when we reach this block at this call depth.
    Join { block: BlockId, depth: usize },
    /// Exit when call depth drops below this.
    Return { depth: usize },
}

/// Thread execution state.
#[derive(Debug)]
pub struct Thread {
    call_stack: Vec<Frame>,
    registers: Vec<Value>,
    symbolic_registers: BitSet,
    done: bool,
    has_result: bool,
    /// Set when the thread is blocked on a host/import call.
    /// Contains the destination register for the return value.
    pending_call_dst: Option<Option<Reg>>,
    /// Set when the thread is blocked on a private branch.
    pending_branch: bool,
    /// Active private CF region exit condition, if any.
    private_cf: Option<PrivateCfExit>,
}

impl Thread {
    pub fn new() -> Self {
        Self {
            call_stack: Vec::new(),
            registers: Vec::new(),
            symbolic_registers: BitSet::new(),
            done: false,
            has_result: false,
            pending_call_dst: None,
            pending_branch: false,
            private_cf: None,
        }
    }

    pub fn in_private_cf(&self) -> bool {
        self.private_cf.is_some()
    }

    pub fn registers(&self) -> &[Value] {
        &self.registers
    }

    pub fn registers_mut(&mut self) -> &mut [Value] {
        &mut self.registers
    }


    pub fn resolve_branch(&mut self, trap: bool) -> Result<(), VmError> {
        if !self.pending_branch {
            return Err(VmError::Internal("no pending branch".into()));
        }
        self.pending_branch = false;
        if trap {
            return Err(Trap::Unreachable.into());
        }
        Ok(())
    }

    pub fn resolve_call(&mut self, value: Option<Value>) -> Result<(), VmError> {
        let dst = self
            .pending_call_dst
            .take()
            .ok_or_else(|| VmError::Internal("no pending host call".into()))?;
        if let Some(reg) = dst {
            match value {
                Some(v) => self.registers[reg as usize] = v,
                None => return Err(VmError::Internal("host call requires return value".into())),
            }
        }
        Ok(())
    }

    pub fn call_stack(&self) -> &[Frame] {
        &self.call_stack
    }

    pub fn call_stack_depth(&self) -> usize {
        self.call_stack.len()
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn call(&mut self, cx: &mut Context<'_>, call: Call) -> Result<(), VmError> {
        let Call { func_idx, params } = call;

        if !self.call_stack.is_empty() {
            todo!("return internal error")
        }

        let Function::Local(func) = cx
            .module
            .function(func_idx)
            .ok_or_else(|| VmError::UndefinedFunction(func_idx))?
        else {
            return Err(VmError::InvalidFunction(func_idx));
        };

        let num_results = func.func_type().results.len();
        if num_results > 1 {
            return Err(VmError::Unsupported("multi-value return".into()));
        }

        self.has_result = num_results > 0;
        let reg_base = num_results;
        let num_args = params.len();

        self.registers.resize(num_results + num_args, Value::I32(0));

        for (i, param) in params.into_iter().enumerate() {
            let abs_reg = (reg_base + i) as u32;
            match param {
                Param::Private(value) => {
                    self.registers[reg_base + i] = value;
                    self.symbolic_registers.insert(abs_reg);
                }
                Param::Public(value) => {
                    self.registers[reg_base + i] = value;
                    self.symbolic_registers.remove(abs_reg);
                }
                Param::Blind(ty) => {
                    self.registers[reg_base + i] = Value::zero(ty);
                    self.symbolic_registers.insert(abs_reg);
                }
            };
        }

        let reg_result = if self.has_result { Some(0) } else { None };
        self.enter_frame(
            cx,
            func_idx,
            func,
            (reg_base as u32..(reg_base + num_args) as u32).collect(),
            reg_result,
        )?;

        Ok(())
    }

    pub fn step(
        &mut self,
        cx: &mut Context<'_>,
        private_eval: bool,
    ) -> Result<StepResult, VmError> {
        if self.pending_branch {
            return Err(VmError::Internal(
                "thread is blocked on a private branch, resolve it first".into(),
            ));
        }
        if self.pending_call_dst.is_some() {
            return Err(VmError::Internal(
                "thread is blocked on a host call, resolve it first".into(),
            ));
        }
        self.check_private_cf_exit();
        let in_private_cf = self.in_private_cf();
        let frame = self
            .call_stack
            .last_mut()
            .ok_or_else(|| VmError::Internal("call already completed".into()))?;

        let func_idx = frame.func_idx;
        let func = match cx.module.function(func_idx) {
            Some(Function::Local(f)) => f,
            _ => return Err(VmError::InvalidFunction(func_idx)),
        };
        match frame.step(
            cx,
            &mut self.registers,
            &mut self.symbolic_registers,
            func.body(),
            private_eval,
            in_private_cf,
        )? {
            FrameStepResult::Continue => {
                self.check_private_cf_exit();
                Ok(StepResult::Continue)
            }
            FrameStepResult::Directive(event) => {
                match &event {
                    Directive::Branch {
                        cond: Some(Operand::Symbol(_)),
                        exit,
                        bail_out,
                        ..
                    } => {
                        // Bail-out branches are publicly deducible — don't
                        // enter private CF, but still require trap resolution.
                        if !bail_out && self.private_cf.is_none() {
                            self.private_cf = Some(match exit {
                                Some(block) => PrivateCfExit::Join {
                                    block: *block,
                                    depth: self.call_stack.len(),
                                },
                                None => PrivateCfExit::Return {
                                    depth: self.call_stack.len(),
                                },
                            });
                        }
                        // Block on private branches (verifier mode only).
                        if !private_eval {
                            self.pending_branch = true;
                            if exit.is_none() {
                                self.exit_frame(None)?;
                            }
                        }
                    }
                    // Block on host/import calls until resolved.
                    Directive::Call { dst, .. } => {
                        self.pending_call_dst = Some(*dst);
                    }
                    _ => {}
                }
                self.check_private_cf_exit();
                Ok(StepResult::Directive(event))
            }
            FrameStepResult::Call {
                func_idx,
                args,
                dst,
            } => {
                let func = match cx.module.function(func_idx) {
                    Some(Function::Local(f)) => f,
                    _ => return Err(VmError::UndefinedFunction(func_idx)),
                };
                let reg_args: Vec<Reg> = args
                    .iter()
                    .map(|a| match a {
                        Operand::Symbol(r) => *r,
                        _ => unreachable!("local call args should be symbolic"),
                    })
                    .collect();
                self.enter_frame(cx, func_idx, func, reg_args, dst)?;
                Ok(StepResult::Directive(Directive::Call {
                    dst,
                    func_idx,
                    args,
                }))
            }
            FrameStepResult::Return { return_reg } => {
                self.exit_frame(return_reg)?;
                self.check_private_cf_exit();
                if self.call_stack.is_empty() {
                    return self.complete();
                }
                Ok(StepResult::Directive(Directive::Return { return_reg }))
            }
        }
    }

    fn check_private_cf_exit(&mut self) {
        let exited = match self.private_cf {
            Some(PrivateCfExit::Join { block, depth }) => {
                // Exit when we reach the join block at the right depth,
                // OR when the call depth drops (function returned/trapped).
                self.call_stack.len() < depth
                    || (self.call_stack.len() == depth
                        && self
                            .call_stack
                            .last()
                            .map(|f| f.current_block == block && f.ip == 0)
                            .unwrap_or(false))
            }
            Some(PrivateCfExit::Return { depth }) => self.call_stack.len() < depth,
            None => false,
        };
        if exited {
            self.private_cf = None;
        }
    }

    fn enter_frame(
        &mut self,
        _cx: &mut Context<'_>,
        func_idx: u32,
        func: &LocalFunction,
        args: Vec<Reg>,
        reg_result: Option<Reg>,
    ) -> Result<(), VmError> {
        if func.func_type().results.len() > 1 {
            return Err(VmError::Unsupported("multi-value return".into()));
        }

        let func_type = func.func_type();
        let num_regs = func.register_count() as usize;
        let reg_base = self.registers.len();

        let target_len = reg_base + num_regs;
        if self.registers.len() < target_len {
            self.registers.resize(target_len, Value::I32(0));
        }

        // Copy args (preserving symbolic state)
        for (i, arg) in args.iter().enumerate() {
            let abs_src = *arg as usize;
            let abs_dst = reg_base + i;
            self.registers[abs_dst] = self.registers[abs_src];
            if self.symbolic_registers.contains(*arg) {
                self.symbolic_registers.insert(abs_dst as u32);
            } else {
                self.symbolic_registers.remove(abs_dst as u32);
            }
        }

        // Zero declared locals
        let num_params = func_type.params.len();
        let mut local_idx = num_params;
        for local in func.locals() {
            let zero = Value::zero(local.ty);
            for _ in 0..local.count {
                let abs = (reg_base + local_idx) as u32;
                self.registers[reg_base + local_idx] = zero;
                self.symbolic_registers.remove(abs);
                local_idx += 1;
            }
        }

        self.call_stack.push(Frame {
            func_idx,
            reg_base: reg_base as Reg,
            num_regs: num_regs as u32,
            current_block: func.body().entry,
            ip: 0,
            reg_result,
        });

        Ok(())
    }

    fn exit_frame(&mut self, _return_reg: Option<Reg>) -> Result<(), VmError> {
        let frame = self
            .call_stack
            .pop()
            .ok_or_else(|| VmError::Internal("no frame to exit".into()))?;
        // Clear the popped frame's registers from the symbolic map so
        // they don't leak taint into the next call at the same reg_base.
        self.symbolic_registers
            .remove_range(frame.reg_base, frame.num_regs as usize);
        Ok(())
    }

    fn complete(&mut self) -> Result<StepResult, VmError> {
        let result = if self.has_result {
            Some(self.registers[0])
        } else {
            None
        };
        Ok(StepResult::Done { result })
    }
}

/// A call frame representing a function invocation.
#[derive(Debug)]
pub struct Frame {
    func_idx: u32,
    reg_base: Reg,
    num_regs: u32,
    reg_result: Option<Reg>,
    current_block: BlockId,
    ip: usize,
}

impl Frame {
    pub fn func_idx(&self) -> u32 {
        self.func_idx
    }

    pub fn reg_base(&self) -> Reg {
        self.reg_base
    }

    pub fn reg_result(&self) -> Option<Reg> {
        self.reg_result
    }

    pub fn current_block(&self) -> BlockId {
        self.current_block
    }

    pub fn ip(&self) -> usize {
        self.ip
    }

    fn abs(&self, reg: Reg) -> u32 {
        self.reg_base + reg
    }

    fn get(&self, registers: &[Value], reg: Reg) -> Value {
        registers[self.reg_base as usize + reg as usize]
    }

    fn set(&self, registers: &mut [Value], reg: Reg, value: Value) {
        registers[self.reg_base as usize + reg as usize] = value;
    }

    fn is_symbolic(&self, symbolic: &BitSet, reg: Reg) -> bool {
        symbolic.contains(self.abs(reg))
    }

    fn operand(&self, registers: &[Value], symbolic: &BitSet, reg: Reg) -> Operand {
        if self.is_symbolic(symbolic, reg) {
            Operand::Symbol(reg)
        } else {
            Operand::Concrete(self.get(registers, reg))
        }
    }

    fn set_clear(&self, registers: &mut [Value], symbolic: &mut BitSet, reg: Reg, value: Value) {
        self.set(registers, reg, value);
        symbolic.remove(self.abs(reg));
    }

    fn set_symbolic(&self, symbolic: &mut BitSet, reg: Reg) {
        symbolic.insert(self.abs(reg));
    }

    fn advance_ip(&mut self) {
        self.ip += 1;
    }

    fn step(
        &mut self,
        cx: &mut Context<'_>,
        registers: &mut [Value],
        symbolic: &mut BitSet,
        body: &FunctionBody,
        private_eval: bool,
        in_private_cf: bool,
    ) -> Result<FrameStepResult, VmError> {
        let block = &body.blocks[self.current_block.index()];

        if self.ip >= block.body.len() {
            return self.execute_terminator(
                cx,
                registers,
                symbolic,
                &block.terminator,
                body,
                private_eval,
                in_private_cf,
            );
        }

        let instr = block.body[self.ip].clone();
        match &instr {
            Instruction::Nop => self.advance_ip(),

            Instruction::I32Const { dst, val } => {
                self.set_clear(registers, symbolic, *dst, Value::from(*val));
                self.advance_ip();
            }

            Instruction::I64Const { dst, val } => {
                self.set_clear(registers, symbolic, *dst, Value::from(*val));
                self.advance_ip();
            }

            Instruction::F32Const { dst, val } => {
                self.set_clear(registers, symbolic, *dst, Value::from(f32::from_bits(*val)));
                self.advance_ip();
            }

            Instruction::F64Const { dst, val } => {
                self.set_clear(registers, symbolic, *dst, Value::from(f64::from_bits(*val)));
                self.advance_ip();
            }

            Instruction::Copy { dst, src } => {
                let value = self.get(registers, *src);
                let src_symbolic = self.is_symbolic(symbolic, *src);
                let directive = if src_symbolic {
                    let d = Directive::Op(Op::Copy {
                        dst: *dst,
                        src: *src,
                    });
                    if !private_eval {
                        self.set(registers, *dst, value);
                        symbolic.insert(self.abs(*dst));
                        self.advance_ip();
                        return Ok(FrameStepResult::Directive(d));
                    }
                    symbolic.insert(self.abs(*dst));
                    Some(d)
                } else {
                    symbolic.remove(self.abs(*dst));
                    None
                };
                self.set(registers, *dst, value);
                self.advance_ip();
                if let Some(d) = directive {
                    return Ok(FrameStepResult::Directive(d));
                }
            }

            Instruction::GlobalGet { dst, global_idx } => {
                let value = cx
                    .global
                    .globals()
                    .get(*global_idx as usize)
                    .cloned()
                    .ok_or(VmError::UndefinedGlobal(*global_idx))?;
                let is_sym = cx.global.is_global_symbolic(*global_idx);
                let directive = if is_sym {
                    let d = Directive::Op(Op::GlobalGet {
                        dst: *dst,
                        global_idx: *global_idx,
                    });
                    if !private_eval {
                        self.set(registers, *dst, value);
                        symbolic.insert(self.abs(*dst));
                        self.advance_ip();
                        return Ok(FrameStepResult::Directive(d));
                    }
                    symbolic.insert(self.abs(*dst));
                    Some(d)
                } else {
                    symbolic.remove(self.abs(*dst));
                    None
                };
                self.set(registers, *dst, value);
                self.advance_ip();
                if let Some(d) = directive {
                    return Ok(FrameStepResult::Directive(d));
                }
            }

            Instruction::GlobalSet { global_idx, src } => {
                let value = self.get(registers, *src);
                let is_sym = self.is_symbolic(symbolic, *src);
                let op_src = self.operand(registers, symbolic, *src);
                let directive = if is_sym {
                    let d = Directive::Op(Op::GlobalSet {
                        global_idx: *global_idx,
                        src: op_src,
                    });
                    if !private_eval {
                        let globals = cx.global.globals_mut();
                        if *global_idx as usize >= globals.len() {
                            return Err(VmError::UndefinedGlobal(*global_idx));
                        }
                        globals[*global_idx as usize] = value;
                        cx.global.mark_global_symbolic(*global_idx);
                        self.advance_ip();
                        return Ok(FrameStepResult::Directive(d));
                    }
                    cx.global.mark_global_symbolic(*global_idx);
                    Some(d)
                } else {
                    cx.global.mark_global_clear(*global_idx);
                    None
                };
                let globals = cx.global.globals_mut();
                if *global_idx as usize >= globals.len() {
                    return Err(VmError::UndefinedGlobal(*global_idx));
                }
                globals[*global_idx as usize] = value;
                self.advance_ip();
                if let Some(d) = directive {
                    return Ok(FrameStepResult::Directive(d));
                }
            }

            Instruction::Select {
                dst,
                cond,
                if_true,
                if_false,
            } => {
                let cond_sym = self.is_symbolic(symbolic, *cond);
                let true_sym = self.is_symbolic(symbolic, *if_true);
                let false_sym = self.is_symbolic(symbolic, *if_false);
                let select_op = || {
                    Directive::Op(Op::Select {
                        dst: *dst,
                        cond: self.operand(registers, symbolic, *cond),
                        if_true: self.operand(registers, symbolic, *if_true),
                        if_false: self.operand(registers, symbolic, *if_false),
                    })
                };

                if !cond_sym {
                    let condition = self.get(registers, *cond).as_i32()?;
                    let result = if condition != 0 {
                        self.get(registers, *if_true)
                    } else {
                        self.get(registers, *if_false)
                    };
                    let result_sym = if condition != 0 { true_sym } else { false_sym };
                    let directive = if result_sym {
                        let d = select_op();
                        if !private_eval {
                            self.set(registers, *dst, result);
                            symbolic.insert(self.abs(*dst));
                            self.advance_ip();
                            return Ok(FrameStepResult::Directive(d));
                        }
                        symbolic.insert(self.abs(*dst));
                        Some(d)
                    } else {
                        symbolic.remove(self.abs(*dst));
                        None
                    };
                    self.set(registers, *dst, result);
                    self.advance_ip();
                    if let Some(d) = directive {
                        return Ok(FrameStepResult::Directive(d));
                    }
                } else {
                    // Symbolic condition — result is symbolic.
                    let d = select_op();
                    if !private_eval {
                        let val_true = self.get(registers, *if_true);
                        self.set(registers, *dst, val_true);
                        symbolic.insert(self.abs(*dst));
                        self.advance_ip();
                        return Ok(FrameStepResult::Directive(d));
                    }
                    // private_eval: evaluate condition from register value and select
                    let condition = self.get(registers, *cond).as_i32()?;
                    let result = if condition != 0 {
                        self.get(registers, *if_true)
                    } else {
                        self.get(registers, *if_false)
                    };
                    symbolic.insert(self.abs(*dst));
                    self.set(registers, *dst, result);
                    self.advance_ip();
                    return Ok(FrameStepResult::Directive(d));
                }
            }

            Instruction::I32Load { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    4,
                    private_eval,
                    Op::I32Load {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i32(a).map(Value::from),
                );
            }

            Instruction::I32Store { addr, val, memarg } => {
                let store_op = Directive::Op(Op::I32Store {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    4,
                    private_eval,
                    in_private_cf,
                    false,
                    store_op,
                );
            }

            Instruction::I64Load { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    8,
                    private_eval,
                    Op::I64Load {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i64(a).map(Value::from),
                );
            }

            Instruction::I64Store { addr, val, memarg } => {
                let store_op = Directive::Op(Op::I64Store {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    8,
                    private_eval,
                    in_private_cf,
                    false,
                    store_op,
                );
            }

            Instruction::I32Load8S { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    1,
                    private_eval,
                    Op::I32Load8S {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i32_partial(a, 1, true).map(Value::from),
                );
            }
            Instruction::I32Load8U { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    1,
                    private_eval,
                    Op::I32Load8U {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i32_partial(a, 1, false).map(Value::from),
                );
            }
            Instruction::I32Load16S { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    2,
                    private_eval,
                    Op::I32Load16S {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i32_partial(a, 2, true).map(Value::from),
                );
            }
            Instruction::I32Load16U { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    2,
                    private_eval,
                    Op::I32Load16U {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i32_partial(a, 2, false).map(Value::from),
                );
            }

            Instruction::I64Load8S { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    1,
                    private_eval,
                    Op::I64Load8S {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i64_partial(a, 1, true).map(Value::from),
                );
            }
            Instruction::I64Load8U { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    1,
                    private_eval,
                    Op::I64Load8U {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i64_partial(a, 1, false).map(Value::from),
                );
            }
            Instruction::I64Load16S { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    2,
                    private_eval,
                    Op::I64Load16S {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i64_partial(a, 2, true).map(Value::from),
                );
            }
            Instruction::I64Load16U { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    2,
                    private_eval,
                    Op::I64Load16U {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i64_partial(a, 2, false).map(Value::from),
                );
            }
            Instruction::I64Load32S { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    4,
                    private_eval,
                    Op::I64Load32S {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i64_partial(a, 4, true).map(Value::from),
                );
            }
            Instruction::I64Load32U { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    4,
                    private_eval,
                    Op::I64Load32U {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_i64_partial(a, 4, false).map(Value::from),
                );
            }

            Instruction::I32Store8 { addr, val, memarg } => {
                let store_op = Directive::Op(Op::I32Store8 {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    1,
                    private_eval,
                    in_private_cf,
                    true,
                    store_op,
                );
            }
            Instruction::I32Store16 { addr, val, memarg } => {
                let store_op = Directive::Op(Op::I32Store16 {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    2,
                    private_eval,
                    in_private_cf,
                    true,
                    store_op,
                );
            }
            Instruction::I64Store8 { addr, val, memarg } => {
                let store_op = Directive::Op(Op::I64Store8 {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    1,
                    private_eval,
                    in_private_cf,
                    true,
                    store_op,
                );
            }
            Instruction::I64Store16 { addr, val, memarg } => {
                let store_op = Directive::Op(Op::I64Store16 {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    2,
                    private_eval,
                    in_private_cf,
                    true,
                    store_op,
                );
            }
            Instruction::I64Store32 { addr, val, memarg } => {
                let store_op = Directive::Op(Op::I64Store32 {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    4,
                    private_eval,
                    in_private_cf,
                    true,
                    store_op,
                );
            }

            Instruction::F32Load { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    4,
                    private_eval,
                    Op::F32Load {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_f32(a).map(Value::from),
                );
            }

            Instruction::F64Load { dst, addr, memarg } => {
                return self.do_load(
                    cx,
                    registers,
                    symbolic,
                    *dst,
                    *addr,
                    *memarg,
                    8,
                    private_eval,
                    Op::F64Load {
                        dst: *dst,
                        addr: *addr,
                        memarg: *memarg,
                    },
                    |mem, a| mem.read_f64(a).map(Value::from),
                );
            }

            Instruction::F32Store { addr, val, memarg } => {
                let store_op = Directive::Op(Op::F32Store {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    4,
                    private_eval,
                    in_private_cf,
                    false,
                    store_op,
                );
            }

            Instruction::F64Store { addr, val, memarg } => {
                let store_op = Directive::Op(Op::F64Store {
                    addr: self.operand(registers, symbolic, *addr),
                    val: self.operand(registers, symbolic, *val),
                    memarg: *memarg,
                });
                return self.do_store(
                    cx,
                    registers,
                    symbolic,
                    *addr,
                    *val,
                    *memarg,
                    8,
                    private_eval,
                    in_private_cf,
                    false,
                    store_op,
                );
            }

            Instruction::MemorySize { dst } => {
                let memory = cx.global.memory().ok_or(VmError::MemoryNotDefined)?;
                let pages = memory.size_pages();
                self.set_clear(registers, symbolic, *dst, Value::from(pages as i32));
                self.advance_ip();
            }

            Instruction::MemoryGrow { dst, pages } => {
                let delta = self.get(registers, *pages).as_i32()?;
                let memory = cx.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                let result = match memory.grow(delta as u32) {
                    Ok(prev_pages) => prev_pages as i32,
                    Err(_) => -1i32,
                };
                self.set_clear(registers, symbolic, *dst, Value::from(result));
                self.advance_ip();
            }

            Instruction::MemoryFill { dest, val, len } => {
                let size = self.get(registers, *len).as_i32()? as usize;
                let byte_val = self.get(registers, *val).as_i32()? as u8;
                let dest_addr =
                    self.get(registers, *dest)
                        .as_i32()
                        .map_err(|_| VmError::SymbolicAddress)? as usize;
                let memory = cx.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                memory.fill(dest_addr, byte_val, size)?;
                // Concrete fill clears symbolic state at destination.
                if !in_private_cf {
                    cx.global
                        .memory_taint_mut()
                        .remove_range(dest_addr as u32, size);
                }
                self.advance_ip();
            }

            Instruction::MemoryCopy { dest, src, len } => {
                let size = self.get(registers, *len).as_i32()? as usize;
                let src_addr = self
                    .get(registers, *src)
                    .as_i32()
                    .map_err(|_| VmError::SymbolicAddress)? as usize;
                let dest_addr =
                    self.get(registers, *dest)
                        .as_i32()
                        .map_err(|_| VmError::SymbolicAddress)? as usize;
                let memory = cx.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                memory.copy(dest_addr, src_addr, size)?;
                if !in_private_cf {
                    cx.global
                        .memory_taint_mut()
                        .copy(src_addr as u32, dest_addr as u32, size);
                }
                self.advance_ip();
            }

            Instruction::MemoryInit {
                data_idx,
                dest,
                src_offset,
                len,
            } => {
                let size = self.get(registers, *len).as_i32()? as usize;
                let offset = self.get(registers, *src_offset).as_i32()? as usize;
                let dest_addr =
                    self.get(registers, *dest)
                        .as_i32()
                        .map_err(|_| VmError::SymbolicAddress)? as usize;
                let data = cx
                    .module
                    .data()
                    .get(*data_idx as usize)
                    .ok_or_else(|| VmError::Internal("invalid data segment".into()))?;
                let memory = cx.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                let src_data = data
                    .data
                    .get(offset..offset + size)
                    .ok_or_else(|| VmError::Internal("data segment out of bounds".into()))?;
                memory.write_bytes(dest_addr as u32, src_data)?;
                self.advance_ip();
            }

            Instruction::DataDrop { .. } => {
                self.advance_ip();
            }

            Instruction::Call {
                dst,
                func_idx,
                args,
            } => {
                return self.do_call(
                    cx,
                    registers,
                    symbolic,
                    *func_idx,
                    args,
                    *dst,
                    private_eval,
                    in_private_cf,
                );
            }

            Instruction::CallIndirect {
                dst,
                type_index,
                table_index: _,
                table_idx,
                args,
            } => {
                let idx = self
                    .get(registers, *table_idx)
                    .as_i32()
                    .map_err(|_| VmError::SymbolicValue)?;

                let table = cx.global.table();
                if idx < 0 || idx as usize >= table.len() {
                    return Err(Trap::UndefinedElement.into());
                }
                let callee_idx = table[idx as usize].ok_or(Trap::UndefinedElement)?;

                let expected_type = &cx.module.types()[*type_index as usize];
                let callee = cx
                    .module
                    .function(callee_idx)
                    .ok_or(VmError::UndefinedFunction(callee_idx))?;
                if callee.func_type() != expected_type {
                    return Err(Trap::IndirectCallTypeMismatch.into());
                }

                return self.do_call(
                    cx,
                    registers,
                    symbolic,
                    callee_idx,
                    args,
                    *dst,
                    private_eval,
                    in_private_cf,
                );
            }

            Instruction::Arith(arith_instr) => {
                return self.execute_arith(registers, symbolic, arith_instr, private_eval);
            }

            Instruction::RefNull { dst, .. } => {
                self.set_clear(registers, symbolic, *dst, Value::from(0i32));
                self.advance_ip();
            }

            Instruction::RefIsNull { dst, src } => {
                let val = self.get(registers, *src).as_i32()?;
                let result = if val == 0 { 1i32 } else { 0i32 };
                self.set_clear(registers, symbolic, *dst, Value::from(result));
                self.advance_ip();
            }

            Instruction::RefFunc { dst, func_idx } => {
                self.set_clear(registers, symbolic, *dst, Value::from(*func_idx as i32));
                self.advance_ip();
            }
        }

        Ok(FrameStepResult::Continue)
    }

    fn execute_arith(
        &mut self,
        registers: &mut [Value],
        symbolic: &mut BitSet,
        instr: &InstructionArith,
        private_eval: bool,
    ) -> Result<FrameStepResult, VmError> {
        match instr {
            InstructionArith::Unary(unary) => {
                let directive = if self.is_symbolic(symbolic, unary.src) {
                    let d = Directive::Op(Op::Unary {
                        dst: unary.dst,
                        op: unary.op,
                        src: unary.src,
                    });
                    if !private_eval {
                        self.set_symbolic(symbolic, unary.dst);
                        self.advance_ip();
                        return Ok(FrameStepResult::Directive(d));
                    }
                    symbolic.insert(self.abs(unary.dst));
                    Some(d)
                } else {
                    symbolic.remove(self.abs(unary.dst));
                    None
                };
                let reg_base = self.reg_base as usize;
                let (dst, val) =
                    arithmetic::execute(instr, |reg| Ok(registers[reg_base + reg as usize]))?;
                registers[reg_base + dst as usize] = val;
                self.advance_ip();
                if let Some(d) = directive {
                    return Ok(FrameStepResult::Directive(d));
                }
            }
            InstructionArith::Binary(binary) => {
                let lhs_sym = self.is_symbolic(symbolic, binary.lhs);
                let rhs_sym = self.is_symbolic(symbolic, binary.rhs);
                let directive = if lhs_sym || rhs_sym {
                    let d = Directive::Op(Op::Binary {
                        dst: binary.dst,
                        op: binary.op,
                        lhs: self.operand(registers, symbolic, binary.lhs),
                        rhs: self.operand(registers, symbolic, binary.rhs),
                    });
                    if !private_eval {
                        self.set_symbolic(symbolic, binary.dst);
                        self.advance_ip();
                        return Ok(FrameStepResult::Directive(d));
                    }
                    symbolic.insert(self.abs(binary.dst));
                    Some(d)
                } else {
                    symbolic.remove(self.abs(binary.dst));
                    None
                };
                let reg_base = self.reg_base as usize;
                let (dst, val) =
                    arithmetic::execute(instr, |reg| Ok(registers[reg_base + reg as usize]))?;
                registers[reg_base + dst as usize] = val;
                self.advance_ip();
                if let Some(d) = directive {
                    return Ok(FrameStepResult::Directive(d));
                }
            }
        }
        Ok(FrameStepResult::Continue)
    }

    fn do_load(
        &mut self,
        cx: &mut Context<'_>,
        registers: &mut [Value],
        symbolic: &mut BitSet,
        dst: Reg,
        addr: Reg,
        memarg: ir::MemArg,
        byte_size: u32,
        private_eval: bool,
        op: Op,
        read_full: impl Fn(&Memory, u32) -> Result<Value, VmError>,
    ) -> Result<FrameStepResult, VmError> {
        let addr_sym = self.is_symbolic(symbolic, addr);
        let addr_val = self.get(registers, addr).as_i32()?;
        let eff_addr = (addr_val as u64 + memarg.offset as u64) as u32;
        let memory = cx.global.memory().ok_or(VmError::MemoryNotDefined)?;

        let is_symbolic =
            addr_sym || cx.global.memory_taint().compute_mask(eff_addr, byte_size) != 0;

        if !is_symbolic {
            self.set_clear(registers, symbolic, dst, read_full(memory, eff_addr)?);
            self.advance_ip();
            return Ok(FrameStepResult::Continue);
        }

        let d = Directive::Op(op);
        if !private_eval {
            self.set_symbolic(symbolic, dst);
            self.advance_ip();
            return Ok(FrameStepResult::Directive(d));
        }
        symbolic.insert(self.abs(dst));
        self.set(registers, dst, read_full(memory, eff_addr)?);
        self.advance_ip();
        Ok(FrameStepResult::Directive(d))
    }

    fn do_store(
        &mut self,
        cx: &mut Context<'_>,
        registers: &mut [Value],
        symbolic: &mut BitSet,
        addr: Reg,
        val: Reg,
        memarg: ir::MemArg,
        byte_size: usize,
        private_eval: bool,
        in_private_cf: bool,
        mark_all_sym_on_sym_addr: bool,
        store_op: Directive,
    ) -> Result<FrameStepResult, VmError> {
        if self.is_symbolic(symbolic, addr) {
            if !private_eval {
                if mark_all_sym_on_sym_addr {
                    if let Some(memory) = cx.global.memory() {
                        let len = memory.len();
                        cx.global.memory_taint_mut().insert_range(0, len);
                    }
                }
                self.advance_ip();
                return Ok(FrameStepResult::Directive(store_op));
            }
            let addr_val = self.get(registers, addr).as_i32()?;
            let eff_addr = (addr_val as u64 + memarg.offset as u64) as u32;
            let bytes = self.get(registers, val).to_le_bytes();
            let memory = cx.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
            memory.write_bytes(eff_addr, &bytes[..byte_size])?;
            cx.global
                .memory_taint_mut()
                .insert_range(eff_addr, byte_size);
            self.advance_ip();
            return Ok(FrameStepResult::Directive(store_op));
        }
        let addr_val = self.get(registers, addr).as_i32()?;
        let eff_addr = (addr_val as u64 + memarg.offset as u64) as u32;
        let val_sym = self.is_symbolic(symbolic, val);

        if !val_sym {
            let bytes = self.get(registers, val).to_le_bytes();
            let memory = cx.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
            memory.write_bytes(eff_addr, &bytes[..byte_size])?;
            if !in_private_cf {
                cx.global
                    .memory_taint_mut()
                    .remove_range(eff_addr, byte_size);
            }
        } else {
            cx.global
                .memory_taint_mut()
                .insert_range(eff_addr, byte_size);
            if !private_eval {
                self.advance_ip();
                return Ok(FrameStepResult::Directive(store_op));
            }
            let bytes = self.get(registers, val).to_le_bytes();
            let memory = cx.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
            memory.write_bytes(eff_addr, &bytes[..byte_size])?;
            self.advance_ip();
            return Ok(FrameStepResult::Directive(store_op));
        }
        self.advance_ip();
        Ok(FrameStepResult::Continue)
    }

    fn do_call(
        &mut self,
        cx: &mut Context<'_>,
        registers: &mut [Value],
        symbolic: &mut BitSet,
        func_idx: u32,
        args: &[Reg],
        dst: Option<Reg>,
        private_eval: bool,
        in_private_cf: bool,
    ) -> Result<FrameStepResult, VmError> {
        let func = cx
            .module
            .function(func_idx)
            .ok_or(VmError::UndefinedFunction(func_idx))?;

        match func {
            Function::Import(import) => self.handle_import(
                cx,
                registers,
                symbolic,
                import,
                func_idx,
                dst,
                args,
                private_eval,
                in_private_cf,
            ),
            Function::Local(_) => {
                let dst = dst.map(|r| self.reg_base + r);
                let args: Vec<Operand> = args
                    .iter()
                    .map(|&r| Operand::Symbol(self.reg_base + r))
                    .collect();

                self.advance_ip();
                Ok(FrameStepResult::Call {
                    func_idx,
                    args,
                    dst,
                })
            }
        }
    }

    fn handle_import(
        &mut self,
        cx: &mut Context<'_>,
        registers: &mut [Value],
        symbolic: &mut BitSet,
        import: &ImportedFunction,
        func_idx: u32,
        dst: Option<Reg>,
        arg_regs: &[Reg],
        _private_eval: bool,
        _in_private_cf: bool,
    ) -> Result<FrameStepResult, VmError> {
        match (import.module(), import.name()) {
            ("wasi_snapshot_preview1", "fd_write") => {
                let fd = self.get(registers, arg_regs[0]).as_i32().unwrap_or(0);
                let iovs = self.get(registers, arg_regs[1]).as_i32().unwrap_or(0) as u32;
                let iovs_len = self.get(registers, arg_regs[2]).as_i32().unwrap_or(0) as u32;
                let nwritten_ptr = self.get(registers, arg_regs[3]).as_i32().unwrap_or(0) as u32;

                let memory = cx.global.memory_mut().ok_or(VmError::MemoryNotDefined)?;
                let mut total_written = 0u32;

                for i in 0..iovs_len {
                    let iov_addr = iovs + i * 8;
                    let ptr_bytes = memory.read_bytes(iov_addr, 4)?;
                    let len_bytes = memory.read_bytes(iov_addr + 4, 4)?;
                    let ptr = u32::from_le_bytes([
                        ptr_bytes[0],
                        ptr_bytes[1],
                        ptr_bytes[2],
                        ptr_bytes[3],
                    ]);
                    let len = u32::from_le_bytes([
                        len_bytes[0],
                        len_bytes[1],
                        len_bytes[2],
                        len_bytes[3],
                    ]);

                    if fd == 1 || fd == 2 {
                        let data = memory.read_bytes(ptr, len as usize)?;
                        if let Ok(s) = std::str::from_utf8(&data) {
                            eprint!("{}", s);
                        }
                    }
                    total_written += len;
                }

                memory.write_bytes(nwritten_ptr, &total_written.to_le_bytes())?;

                let d = dst
                    .ok_or_else(|| VmError::Internal("fd_write requires return register".into()))?;
                self.set_clear(registers, symbolic, d, Value::from(0i32));
                self.advance_ip();
                Ok(FrameStepResult::Continue)
            }
            ("wasi_snapshot_preview1", "proc_exit") => Err(Trap::Unreachable.into()),
            ("mpz", "symbolic") => {
                if dst.is_some() {
                    return Err(VmError::Internal(
                        "mpz::symbolic has no return value".into(),
                    ));
                }
                let ptr = self.get(registers, arg_regs[0]).as_i32()? as u32;
                let len = self.get(registers, arg_regs[1]).as_i32()? as usize;
                cx.global.memory_taint_mut().insert_range(ptr, len);
                self.advance_ip();
                Ok(FrameStepResult::Continue)
            }
            (
                "mpz",
                "decode_i32" | "decode_i64" | "decode_f32" | "decode_f64" | "decode_wait_i32"
                | "decode_wait_i64" | "decode_wait_f32" | "decode_wait_f64" | "decode_mem"
                | "decode_mem_wait" | "alloc" | "free",
            ) => {
                let args: Vec<Operand> = arg_regs
                    .iter()
                    .map(|&r| self.operand(registers, symbolic, r))
                    .collect();
                self.advance_ip();
                Ok(FrameStepResult::Directive(Directive::Call {
                    dst,
                    func_idx,
                    args,
                }))
            }
            _ => Err(VmError::Unsupported(format!(
                "import not found: {}::{}",
                import.module(),
                import.name()
            ))),
        }
    }

    fn jump_to(&mut self, target: BlockId) {
        self.current_block = target;
        self.ip = 0;
    }

    fn execute_terminator(
        &mut self,
        cx: &mut Context<'_>,
        registers: &mut [Value],
        symbolic: &mut BitSet,
        terminator: &Terminator,
        _body: &FunctionBody,
        private_eval: bool,
        in_private_cf: bool,
    ) -> Result<FrameStepResult, VmError> {
        match terminator {
            Terminator::Jump { target } => {
                self.jump_to(*target);
                Ok(FrameStepResult::Directive(Directive::Branch {
                    func_idx: self.func_idx,
                    block: self.current_block,
                    cond: None,
                    exit: None,
                    bail_out: false,
                }))
            }
            Terminator::BrCond {
                cond,
                then_target,
                else_target,
                join,
                region,
            } => {
                if self.is_symbolic(symbolic, *cond) {
                    if !private_eval {
                        return self.handle_symbolic_branch(
                            cx,
                            registers,
                            symbolic,
                            *cond,
                            *join,
                            region,
                            private_eval,
                            in_private_cf,
                        );
                    }
                    // private_eval: taint via handle_symbolic_branch, then evaluate concretely
                    let result = self.handle_symbolic_branch(
                        cx,
                        registers,
                        symbolic,
                        *cond,
                        *join,
                        region,
                        private_eval,
                        in_private_cf,
                    )?;
                    // Now evaluate the condition concretely and jump
                    let condition = self.get(registers, *cond).as_i32()?;
                    if condition != 0 {
                        self.jump_to(*then_target);
                    } else {
                        self.jump_to(*else_target);
                    }
                    return Ok(result);
                }
                let condition = self.get(registers, *cond).as_i32()?;
                let target = if condition != 0 {
                    *then_target
                } else {
                    *else_target
                };
                self.jump_to(target);
                Ok(FrameStepResult::Directive(Directive::Branch {
                    func_idx: self.func_idx,
                    block: self.current_block,
                    cond: Some(Operand::Concrete(Value::I32(condition))),
                    exit: Some(*join),
                    bail_out: false,
                }))
            }
            Terminator::BrTable {
                idx,
                targets,
                default,
                join,
                region,
            } => {
                if self.is_symbolic(symbolic, *idx) {
                    if !private_eval {
                        return self.handle_symbolic_branch(
                            cx,
                            registers,
                            symbolic,
                            *idx,
                            *join,
                            region,
                            private_eval,
                            in_private_cf,
                        );
                    }
                    let result = self.handle_symbolic_branch(
                        cx,
                        registers,
                        symbolic,
                        *idx,
                        *join,
                        region,
                        private_eval,
                        in_private_cf,
                    )?;
                    // Evaluate concretely
                    let index = self.get(registers, *idx).as_i32()?;
                    let target = if (index as usize) < targets.len() {
                        targets[index as usize]
                    } else {
                        *default
                    };
                    self.jump_to(target);
                    return Ok(result);
                }
                let index = self.get(registers, *idx).as_i32()?;
                let target = if (index as usize) < targets.len() {
                    targets[index as usize]
                } else {
                    *default
                };
                self.jump_to(target);
                Ok(FrameStepResult::Directive(Directive::Branch {
                    func_idx: self.func_idx,
                    block: self.current_block,
                    cond: Some(Operand::Concrete(Value::I32(index))),
                    exit: Some(*join),
                    bail_out: false,
                }))
            }
            Terminator::Return { values } => {
                let return_reg = if !values.is_empty() {
                    let result = self.get(registers, values[0]);
                    let is_sym = self.is_symbolic(symbolic, values[0]);
                    if let Some(idx) = self.reg_result {
                        registers[idx as usize] = result;
                        if is_sym {
                            symbolic.insert(idx);
                        } else {
                            symbolic.remove(idx);
                        }
                    }
                    Some(values[0])
                } else {
                    None
                };
                Ok(FrameStepResult::Return { return_reg })
            }
            Terminator::Unreachable => Err(Trap::Unreachable.into()),
        }
    }

    fn handle_symbolic_branch(
        &mut self,
        cx: &mut Context<'_>,
        _registers: &mut [Value],
        symbolic: &mut BitSet,
        cond_reg: Reg,
        join: BlockId,
        region: &ir::BranchRegion,
        private_eval: bool,
        _in_private_cf: bool,
    ) -> Result<FrameStepResult, VmError> {
        // Taint globals written in the branch region.
        for &global_idx in &region.globals_written {
            cx.global.mark_global_symbolic(global_idx);
        }

        // Taint all memory if any store exists in the branch region.
        if region.has_memory_store {
            if let Some(memory) = cx.global.memory() {
                let len = memory.len();
                cx.global.memory_taint_mut().insert_range(0, len);
            }
        }

        // Mark registers written in the branch region as symbolic.
        for &reg in &region.registers_written {
            symbolic.insert(self.abs(reg));
        }

        // Also taint the absolute result register (outside the frame).
        if let Some(idx) = self.reg_result {
            symbolic.insert(idx);
        }

        let branch_block = self.current_block;

        let exit = if region.join_is_path_independent {
            Some(join)
        } else {
            None
        };

        let bail_out = region.bail_out;

        if private_eval {
            return Ok(FrameStepResult::Directive(Directive::Branch {
                func_idx: self.func_idx,
                block: branch_block,
                cond: Some(Operand::Symbol(cond_reg)),
                exit,
                bail_out,
            }));
        }

        if region.join_is_path_independent {
            self.jump_to(join);
        }

        Ok(FrameStepResult::Directive(Directive::Branch {
            func_idx: self.func_idx,
            block: branch_block,
            cond: Some(Operand::Symbol(cond_reg)),
            exit,
            bail_out,
        }))
    }
}
