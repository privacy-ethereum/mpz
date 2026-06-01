use wasmparser::{BinaryReader, BlockType as WasmBlockType, Operator};

use crate::{
    BasicBlock, BinaryArith, BinaryOp, BlockId, Error, FuncType, FunctionBody, Instruction,
    InstructionArith, LoadKind, MemArg, Reg, Result, StoreKind, Terminator, UnaryArith,
    UnaryOp, UnsupportedFeature, ValidationError,
};

use super::cfg::{Scope, get_br_join, get_br_target};
use super::sections::parse_heap_type;

/// Translator from stack-based WASM to CFG-based register instructions.
pub(super) struct Translator {
    /// Virtual stack: maps stack position to register ID.
    reg_stack: Vec<Reg>,
    /// Next available register (starts after locals).
    next_reg: Reg,
    /// Number of local registers (0..num_locals are reserved).
    num_locals: Reg,
    /// Free list of reusable registers.
    free_regs: Vec<Reg>,
    /// Whether we're in unreachable code.
    unreachable: bool,
    /// Stack of control flow scopes.
    scopes: Vec<Scope>,
    /// All finished basic blocks.
    blocks: Vec<BasicBlock>,
    /// Instructions for the current (in-progress) block.
    current_body: Vec<Instruction>,
    /// BlockId of the current block being built.
    current_block: BlockId,
    /// Next block ID to allocate.
    next_block_id: u32,
}

impl Translator {
    fn new(num_locals: u32) -> Self {
        Self {
            reg_stack: Vec::new(),
            next_reg: Reg(num_locals),
            num_locals: Reg(num_locals),
            free_regs: Vec::new(),
            unreachable: false,
            scopes: Vec::new(),
            blocks: Vec::new(),
            current_body: Vec::new(),
            current_block: BlockId(0),
            next_block_id: 1,
        }
    }

    /// Allocate a new BlockId.
    fn alloc_block(&mut self) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        id
    }

    /// Finish the current block with the given terminator.
    /// Start a new block and return its BlockId.
    fn finish_block(&mut self, terminator: Terminator) -> BlockId {
        let body = std::mem::take(&mut self.current_body);
        let block = BasicBlock { body, terminator };
        // Ensure blocks vec is large enough
        let idx = self.current_block.index();
        if idx >= self.blocks.len() {
            self.blocks.resize(
                idx + 1,
                BasicBlock {
                    body: Vec::new(),
                    terminator: Terminator::Unreachable,
                },
            );
        }
        self.blocks[idx] = block;

        let new_block = self.alloc_block();
        self.current_block = new_block;
        new_block
    }

    /// Finish the current block with the given terminator and switch to the
    /// specified existing block (don't allocate a new one).
    fn finish_block_and_switch_to(&mut self, terminator: Terminator, target: BlockId) {
        let body = std::mem::take(&mut self.current_body);
        let block = BasicBlock { body, terminator };
        let idx = self.current_block.index();
        if idx >= self.blocks.len() {
            self.blocks.resize(
                idx + 1,
                BasicBlock {
                    body: Vec::new(),
                    terminator: Terminator::Unreachable,
                },
            );
        }
        self.blocks[idx] = block;
        self.current_block = target;
    }

    /// Allocate a new register and push it on the virtual stack.
    fn push(&mut self) -> Reg {
        let r = if let Some(r) = self.free_regs.pop() {
            r
        } else {
            let r = self.next_reg;
            self.next_reg = self.next_reg + 1;
            r
        };
        if !self.unreachable {
            self.reg_stack.push(r);
        }
        r
    }

    /// Pop a register from the virtual stack.
    fn pop(&mut self) -> Result<Reg> {
        if self.unreachable {
            return Ok(Reg(0));
        }
        let r = self
            .reg_stack
            .pop()
            .ok_or(ValidationError::StackUnderflow)?;
        // Reclaim non-local, non-aliased registers.
        if r >= self.num_locals {
            self.free_regs.push(r);
        }
        Ok(r)
    }

    /// Peek at the top of the virtual stack.
    fn peek(&self) -> Result<Reg> {
        if self.unreachable {
            return Ok(Reg(0));
        }
        self.reg_stack
            .last()
            .copied()
            .ok_or(Error::Validation(ValidationError::StackUnderflow))
    }

    /// Materialize any aliased references to a local register on the stack.
    /// Called before writing to a local so that existing stack references
    /// to the old value get their own registers.
    fn materialize_local(&mut self, local_reg: Reg) {
        for entry in self.reg_stack.iter_mut() {
            if *entry == local_reg {
                let new_reg = if let Some(r) = self.free_regs.pop() {
                    r
                } else {
                    let r = self.next_reg;
                    self.next_reg = self.next_reg + 1;
                    r
                };
                self.current_body.push(Instruction::Copy {
                    dst: new_reg,
                    src: local_reg,
                });
                *entry = new_reg;
            }
        }
    }

    /// Emit an instruction to the current block.
    fn emit(&mut self, instr: Instruction) {
        self.current_body.push(instr);
    }

    /// Get the branch arity for a given depth.
    fn branch_arity(&self, depth: u32) -> usize {
        let idx = self.scopes.len().saturating_sub(1 + depth as usize);
        if let Some(scope) = self.scopes.get(idx) {
            if scope.is_loop { 0 } else { scope.result_arity }
        } else {
            0
        }
    }

    /// Get the result register for the target block at given depth.
    fn branch_result_reg(&self, depth: u32) -> Option<Reg> {
        let idx = self.scopes.len().saturating_sub(1 + depth as usize);
        self.scopes.get(idx).and_then(|s| s.block_result_reg)
    }

    /// Mark as unreachable.
    fn set_unreachable(&mut self) {
        self.unreachable = true;
    }

    /// Translate a unary arithmetic op.
    fn unary_op(&mut self, op: UnaryOp) -> Result<()> {
        let src = self.pop()?;
        let dst = self.push();
        self.emit(Instruction::Arith(InstructionArith::Unary(UnaryArith {
            op,
            dst,
            src,
        })));
        Ok(())
    }

    /// Translate a binary arithmetic op.
    fn binary_op(&mut self, op: BinaryOp) -> Result<()> {
        let rhs = self.pop()?;
        let lhs = self.pop()?;
        let dst = self.push();
        self.emit(Instruction::Arith(InstructionArith::Binary(BinaryArith {
            op,
            dst,
            lhs,
            rhs,
        })));
        Ok(())
    }

    /// Finish a loop scope at its `End`: fall through to the continuation and
    /// restore the operand stack.
    fn finish_loop(&mut self, scope: Scope) {
        let join_block = scope.continuation;

        // Loop End: fall through to continuation.
        // The loop header is stored in else_block.
        if !self.unreachable {
            self.finish_block_and_switch_to(Terminator::Jump { target: join_block }, join_block);
        } else {
            self.finish_block_and_switch_to(Terminator::Unreachable, join_block);
        }

        // Restore stack
        if self.unreachable {
            self.reg_stack.truncate(scope.stack_height);
        } else {
            let target_height = scope.stack_height + scope.result_arity;
            if self.reg_stack.len() >= target_height {
                self.reg_stack.truncate(target_height);
            }
        }
        self.unreachable = scope.was_unreachable;
    }

    /// Finish an if scope at its `End` (after the then arm or, if present, the
    /// else arm), unifying the branch results and stitching any implicit else.
    fn finish_if(&mut self, scope: Scope) {
        let join_block = scope.continuation;

        if let Some(result_reg) = scope.block_result_reg {
            // Copy fall-through result to unified register
            if !self.unreachable {
                if let Some(&src_reg) = self.reg_stack.last() {
                    if src_reg != result_reg {
                        self.emit(Instruction::Copy {
                            dst: result_reg,
                            src: src_reg,
                        });
                    }
                }
            }

            // Finish current arm with jump to join
            if !self.unreachable {
                self.finish_block_and_switch_to(
                    Terminator::Jump { target: join_block },
                    join_block,
                );
            } else {
                self.finish_block_and_switch_to(Terminator::Unreachable, join_block);
            }

            self.reg_stack.truncate(scope.stack_height);

            let reachable_after =
                !scope.was_unreachable || scope.then_was_reachable || !self.unreachable;

            if reachable_after {
                self.reg_stack.push(result_reg);
            }
            self.unreachable = !reachable_after;
        } else {
            // No result, but still need to handle the else-block.
            // If there was no Else operator, the else_block was allocated
            // but never emitted into. We need to make it jump to join.
            if !scope.then_was_reachable {
                // No Else was encountered (then_was_reachable is only set in Else
                // handler). The else_block needs to be a
                // simple jump to join.
                if let Some(else_block) = scope.else_block {
                    // Finish current (then) block
                    if !self.unreachable {
                        self.finish_block_and_switch_to(
                            Terminator::Jump { target: join_block },
                            else_block,
                        );
                    } else {
                        self.finish_block_and_switch_to(Terminator::Unreachable, else_block);
                    }
                    // else_block just jumps to join
                    self.finish_block_and_switch_to(
                        Terminator::Jump { target: join_block },
                        join_block,
                    );
                }
            } else {
                // Else was encountered, we're finishing the else branch
                if !self.unreachable {
                    self.finish_block_and_switch_to(
                        Terminator::Jump { target: join_block },
                        join_block,
                    );
                } else {
                    self.finish_block_and_switch_to(Terminator::Unreachable, join_block);
                }
            }

            if self.unreachable {
                self.reg_stack.truncate(scope.stack_height);
            } else {
                let target_height = scope.stack_height + scope.result_arity;
                if self.reg_stack.len() >= target_height {
                    self.reg_stack.truncate(target_height);
                }
            }

            // Reachability: if either branch was reachable
            let reachable_after =
                !scope.was_unreachable || scope.then_was_reachable || !self.unreachable;
            self.unreachable = !reachable_after;
        }
    }

    /// Finish a plain block scope at its `End`: jump to the continuation,
    /// unifying the block result if any.
    fn finish_plain_block(&mut self, scope: Scope) {
        let join_block = scope.continuation;

        if let Some(result_reg) = scope.block_result_reg {
            // Copy fall-through result to unified register
            if !self.unreachable {
                if let Some(&src_reg) = self.reg_stack.last() {
                    if src_reg != result_reg {
                        self.emit(Instruction::Copy {
                            dst: result_reg,
                            src: src_reg,
                        });
                    }
                }
            }

            if !self.unreachable {
                self.finish_block_and_switch_to(
                    Terminator::Jump { target: join_block },
                    join_block,
                );
            } else {
                self.finish_block_and_switch_to(Terminator::Unreachable, join_block);
            }

            self.reg_stack.truncate(scope.stack_height);

            let reachable_after = !scope.was_unreachable;
            if reachable_after {
                self.reg_stack.push(result_reg);
            }
            self.unreachable = !reachable_after;
        } else {
            if !self.unreachable {
                self.finish_block_and_switch_to(
                    Terminator::Jump { target: join_block },
                    join_block,
                );
            } else {
                self.finish_block_and_switch_to(Terminator::Unreachable, join_block);
            }

            if self.unreachable {
                self.reg_stack.truncate(scope.stack_height);
            } else {
                let target_height = scope.stack_height + scope.result_arity;
                if self.reg_stack.len() >= target_height {
                    self.reg_stack.truncate(target_height);
                }
            }
            self.unreachable = scope.was_unreachable;
        }
    }
}

pub(super) fn translate_to_registers(
    reader: &mut BinaryReader,
    num_locals: u32,
    func_type: &FuncType,
    all_func_types: &[FuncType],
    all_types: &[FuncType],
) -> Result<(u32, FunctionBody)> {
    let mut t = Translator::new(num_locals);

    while !reader.eof() {
        let op = reader.read_operator()?;
        translate_operator(&mut t, &op, func_type, all_func_types, all_types)?;
    }

    // Emit implicit return if reachable
    if !t.unreachable {
        let num_results = func_type.results.len();
        let terminator = if num_results > 0 && t.reg_stack.len() >= num_results {
            let values: Vec<Reg> = t
                .reg_stack
                .iter()
                .rev()
                .take(num_results)
                .rev()
                .copied()
                .collect();
            Terminator::Return { values }
        } else {
            Terminator::Return { values: vec![] }
        };
        // Finish the last block
        t.finish_block(terminator);
    } else {
        // Even unreachable code needs a terminated block
        t.finish_block(Terminator::Unreachable);
    }

    let body = FunctionBody {
        entry: BlockId(0),
        blocks: t.blocks,
    };

    Ok((t.next_reg.as_u32(), body))
}

fn translate_operator(
    t: &mut Translator,
    op: &Operator,
    func_type: &FuncType,
    all_func_types: &[FuncType],
    all_types: &[FuncType],
) -> Result<()> {
    use Operator::*;

    match op {
        // === Control Flow ===
        Unreachable => {
            t.finish_block(Terminator::Unreachable);
            t.set_unreachable();
        }
        Nop => t.emit(Instruction::Nop),
        Block { blockty } => {
            let arity = block_type_result_arity(blockty, all_types)?;
            let continuation = t.alloc_block();

            let block_result_reg = if arity > 0 {
                let reg = t.next_reg;
                t.next_reg = t.next_reg + 1;
                Some(reg)
            } else {
                None
            };

            t.scopes.push(Scope {
                stack_height: t.reg_stack.len(),
                was_unreachable: t.unreachable,
                result_arity: arity,
                is_loop: false,
                is_if: false,
                block_result_reg,
                then_was_reachable: false,
                continuation,
                else_block: None,
            });
            // Continue emitting into current block (block body)
        }
        Loop { blockty } => {
            let arity = block_type_result_arity(blockty, all_types)?;
            let header = t.alloc_block();
            let continuation = t.alloc_block();

            // Current block jumps to header
            if !t.unreachable {
                t.finish_block_and_switch_to(Terminator::Jump { target: header }, header);
            } else {
                t.current_block = header;
            }

            // For loops, br 0 goes back to header, not continuation.
            // We don't allocate a result reg for loops since br to loop takes 0 values.
            t.scopes.push(Scope {
                stack_height: t.reg_stack.len(),
                was_unreachable: t.unreachable,
                result_arity: arity,
                is_loop: true,
                is_if: false,
                block_result_reg: None,
                then_was_reachable: false,
                continuation,
                // Store header as else_block field (reuse for loop header)
                else_block: Some(header),
            });
        }
        If { blockty } => {
            let cond = t.pop()?;
            let arity = block_type_result_arity(blockty, all_types)?;
            let then_block = t.alloc_block();
            let else_block = t.alloc_block();
            let join_block = t.alloc_block();

            let block_result_reg = if arity > 0 {
                let reg = t.next_reg;
                t.next_reg = t.next_reg + 1;
                Some(reg)
            } else {
                None
            };

            // Current block ends with BrCond
            if !t.unreachable {
                t.finish_block_and_switch_to(
                    Terminator::BrCond {
                        cond,
                        then_target: then_block,
                        else_target: else_block,
                        join: join_block,
                    },
                    then_block,
                );
            } else {
                t.current_block = then_block;
            }

            t.scopes.push(Scope {
                stack_height: t.reg_stack.len(),
                was_unreachable: t.unreachable,
                result_arity: arity,
                is_loop: false,
                is_if: true,
                block_result_reg,
                then_was_reachable: false,
                continuation: join_block,
                else_block: Some(else_block),
            });
        }
        Else => {
            // Finish then-branch, switch to else-branch
            let scope = t
                .scopes
                .last()
                .ok_or(ValidationError::MissingScope("else without enclosing if"))?;
            let join_block = scope.continuation;
            let else_block = scope
                .else_block
                .ok_or(ValidationError::MissingScope("if scope without else block"))?;
            let block_result_reg = scope.block_result_reg;
            let stack_height = scope.stack_height;
            let was_unreachable = scope.was_unreachable;
            let then_was_reachable = !t.unreachable;

            // Copy then-branch result to unified register if needed
            if let Some(result_reg) = block_result_reg {
                if then_was_reachable {
                    if let Some(&src_reg) = t.reg_stack.last() {
                        if src_reg != result_reg {
                            t.emit(Instruction::Copy {
                                dst: result_reg,
                                src: src_reg,
                            });
                        }
                    }
                }
            }

            // Finish then block with jump to join
            if then_was_reachable {
                t.finish_block_and_switch_to(Terminator::Jump { target: join_block }, else_block);
            } else {
                // Then was unreachable, still need to finalize its block
                t.finish_block_and_switch_to(Terminator::Unreachable, else_block);
            }

            // Update scope
            if let Some(scope) = t.scopes.last_mut() {
                scope.then_was_reachable = then_was_reachable;
            }

            // Restore stack for else branch
            t.reg_stack.truncate(stack_height);
            t.unreachable = was_unreachable;
        }
        End => {
            if let Some(scope) = t.scopes.pop() {
                if scope.is_loop {
                    t.finish_loop(scope);
                } else if scope.is_if {
                    t.finish_if(scope);
                } else {
                    t.finish_plain_block(scope);
                }
            }
            // Note: the outermost End (function body) has no scope entry;
            // it's handled by translate_to_registers after the loop.
        }
        Br { relative_depth } => {
            let depth = *relative_depth;
            let arity = t.branch_arity(depth);
            let values: Vec<Reg> = (0..arity).map(|_| t.pop()).collect::<Result<Vec<_>>>()?;

            // Copy to target block's result register
            if let (Some(&src), Some(dst)) = (values.first(), t.branch_result_reg(depth)) {
                if src != dst {
                    t.emit(Instruction::Copy { dst, src });
                }
            }

            match get_br_target(&t.scopes, depth)? {
                Some(target) => {
                    t.finish_block(Terminator::Jump { target });
                }
                None => {
                    // Branch to function level = return
                    t.finish_block(Terminator::Return { values });
                }
            }
            t.set_unreachable();
        }
        BrIf { relative_depth } => {
            let depth = *relative_depth;
            let cond = t.pop()?;
            let arity = t.branch_arity(depth);
            let values: Vec<Reg> = (0..arity).map(|_| t.pop()).collect::<Result<Vec<_>>>()?;

            // Push values back since they may be used if branch not taken
            for r in values.iter().rev() {
                t.reg_stack.push(*r);
            }

            // Copy to target block's result register
            if let (Some(&src), Some(dst)) = (values.first(), t.branch_result_reg(depth)) {
                if src != dst {
                    t.emit(Instruction::Copy { dst, src });
                }
            }

            match get_br_target(&t.scopes, depth)? {
                Some(target) => {
                    let fall_through = t.alloc_block();
                    let join = get_br_join(&t.scopes, depth).unwrap_or(fall_through);
                    t.finish_block_and_switch_to(
                        Terminator::BrCond {
                            cond,
                            then_target: target,
                            else_target: fall_through,
                            join,
                        },
                        fall_through,
                    );
                }
                None => {
                    // Branch to function level = conditional return
                    // If taken: return. If not taken: continue.
                    let return_block = t.alloc_block();
                    let fall_through = t.alloc_block();
                    t.finish_block_and_switch_to(
                        Terminator::BrCond {
                            cond,
                            then_target: return_block,
                            else_target: fall_through,
                            join: fall_through,
                        },
                        fall_through,
                    );
                    // Emit the return block
                    let saved_block = t.current_block;
                    t.current_block = return_block;
                    t.finish_block(Terminator::Return { values });
                    t.current_block = saved_block;
                }
            }
        }
        BrTable { targets } => {
            let table = targets.clone();
            let target_vec = table
                .targets()
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let idx = t.pop()?;
            let arity = t.branch_arity(table.default());
            let values: Vec<Reg> = (0..arity).map(|_| t.pop()).collect::<Result<Vec<_>>>()?;

            // Copy to all unique target result registers
            if let Some(&src) = values.first() {
                let mut seen = std::collections::HashSet::new();
                for &depth in target_vec.iter().chain(std::iter::once(&table.default())) {
                    if let Some(dst) = t.branch_result_reg(depth) {
                        if src != dst && seen.insert(dst) {
                            t.emit(Instruction::Copy { dst, src });
                        }
                    }
                }
            }

            // For br_table targets that go to function level, create return blocks
            let mut block_targets: Vec<BlockId> = Vec::new();
            for &depth in &target_vec {
                match get_br_target(&t.scopes, depth)? {
                    Some(target) => block_targets.push(target),
                    None => {
                        // Function-level branch = return block
                        let ret_block = t.alloc_block();
                        let saved = t.current_block;
                        t.current_block = ret_block;
                        t.finish_block(Terminator::Return {
                            values: values.clone(),
                        });
                        t.current_block = saved;
                        block_targets.push(ret_block);
                    }
                }
            }
            let default = match get_br_target(&t.scopes, table.default())? {
                Some(target) => target,
                None => {
                    let ret_block = t.alloc_block();
                    let saved = t.current_block;
                    t.current_block = ret_block;
                    t.finish_block(Terminator::Return {
                        values: values.clone(),
                    });
                    t.current_block = saved;
                    ret_block
                }
            };

            // Compute join as outermost target scope's continuation
            let default_depth = table.default();
            let max_depth = target_vec
                .iter()
                .chain(std::iter::once(&default_depth))
                .max()
                .copied()
                .unwrap_or(0);
            let join = get_br_join(&t.scopes, max_depth).unwrap_or_else(|| {
                // All targets are function-level returns; allocate a dummy
                // unreachable block as the join.
                let dummy = t.alloc_block();
                let saved = t.current_block;
                t.current_block = dummy;
                t.finish_block(Terminator::Unreachable);
                t.current_block = saved;
                dummy
            });

            t.finish_block(Terminator::BrTable {
                idx,
                targets: block_targets,
                default,
                join,
            });
            t.set_unreachable();
        }
        Return => {
            let values: Vec<Reg> = (0..func_type.results.len())
                .map(|_| t.pop())
                .collect::<Result<Vec<_>>>()?;
            t.finish_block(Terminator::Return { values });
            t.set_unreachable();
        }

        // === Calls ===
        Call { function_index } => {
            let callee_type = all_func_types
                .get(*function_index as usize)
                .ok_or(ValidationError::UnknownFunction(*function_index))?;
            let mut args: Vec<Reg> = (0..callee_type.params.len())
                .map(|_| t.pop())
                .collect::<Result<Vec<_>>>()?;
            args.reverse();

            let dst = if !callee_type.results.is_empty() {
                Some(t.push())
            } else {
                None
            };

            t.emit(Instruction::Call {
                dst,
                func_idx: *function_index,
                args,
            });
        }
        CallIndirect {
            type_index,
            table_index,
            ..
        } => {
            let table_idx = t.pop()?;
            let callee_type = all_types
                .get(*type_index as usize)
                .ok_or(ValidationError::UnknownType(*type_index))?;
            let mut args: Vec<Reg> = (0..callee_type.params.len())
                .map(|_| t.pop())
                .collect::<Result<Vec<_>>>()?;
            args.reverse();

            let dst = if !callee_type.results.is_empty() {
                Some(t.push())
            } else {
                None
            };

            t.emit(Instruction::CallIndirect {
                dst,
                type_index: *type_index,
                table_index: *table_index,
                table_idx,
                args,
            });
        }

        // === Parametric ===
        Drop => {
            t.pop()?;
        }
        Select | TypedSelect { .. } => {
            let cond = t.pop()?;
            let if_false = t.pop()?;
            let if_true = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::Select {
                dst,
                cond,
                if_true,
                if_false,
            });
        }

        // === Variables ===
        LocalGet { local_index } => {
            // Alias: push the local's register directly, no Copy.
            if !t.unreachable {
                t.reg_stack.push(Reg(*local_index));
            }
        }
        LocalSet { local_index } => {
            let src = t.pop()?;
            let dst = Reg(*local_index);
            if dst != src {
                // Materialize any aliases to this local on the stack.
                t.materialize_local(dst);
                t.emit(Instruction::Copy { dst, src });
            }
        }
        LocalTee { local_index } => {
            let src = t.peek()?;
            let dst = Reg(*local_index);
            if dst != src {
                t.materialize_local(dst);
                t.emit(Instruction::Copy { dst, src });
            }
        }
        GlobalGet { global_index } => {
            let dst = t.push();
            t.emit(Instruction::GlobalGet {
                dst,
                global_idx: *global_index,
            });
        }
        GlobalSet { global_index } => {
            let src = t.pop()?;
            t.emit(Instruction::GlobalSet {
                global_idx: *global_index,
                src,
            });
        }

        // === Memory Loads ===
        I32Load { memarg } => emit_load(t, LoadKind::I32, memarg)?,
        I64Load { memarg } => emit_load(t, LoadKind::I64, memarg)?,
        F32Load { memarg } => emit_load(t, LoadKind::F32, memarg)?,
        F64Load { memarg } => emit_load(t, LoadKind::F64, memarg)?,
        I32Load8S { memarg } => emit_load(t, LoadKind::I32Load8S, memarg)?,
        I32Load8U { memarg } => emit_load(t, LoadKind::I32Load8U, memarg)?,
        I32Load16S { memarg } => emit_load(t, LoadKind::I32Load16S, memarg)?,
        I32Load16U { memarg } => emit_load(t, LoadKind::I32Load16U, memarg)?,
        I64Load8S { memarg } => emit_load(t, LoadKind::I64Load8S, memarg)?,
        I64Load8U { memarg } => emit_load(t, LoadKind::I64Load8U, memarg)?,
        I64Load16S { memarg } => emit_load(t, LoadKind::I64Load16S, memarg)?,
        I64Load16U { memarg } => emit_load(t, LoadKind::I64Load16U, memarg)?,
        I64Load32S { memarg } => emit_load(t, LoadKind::I64Load32S, memarg)?,
        I64Load32U { memarg } => emit_load(t, LoadKind::I64Load32U, memarg)?,

        // === Memory Stores ===
        I32Store { memarg } => emit_store(t, StoreKind::I32, memarg)?,
        I64Store { memarg } => emit_store(t, StoreKind::I64, memarg)?,
        F32Store { memarg } => emit_store(t, StoreKind::F32, memarg)?,
        F64Store { memarg } => emit_store(t, StoreKind::F64, memarg)?,
        I32Store8 { memarg } => emit_store(t, StoreKind::I32Store8, memarg)?,
        I32Store16 { memarg } => emit_store(t, StoreKind::I32Store16, memarg)?,
        I64Store8 { memarg } => emit_store(t, StoreKind::I64Store8, memarg)?,
        I64Store16 { memarg } => emit_store(t, StoreKind::I64Store16, memarg)?,
        I64Store32 { memarg } => emit_store(t, StoreKind::I64Store32, memarg)?,

        // === Memory Misc ===
        MemorySize { mem, .. } => {
            if *mem != 0 {
                return Err(UnsupportedFeature::MultiMemory.into());
            }
            let dst = t.push();
            t.emit(Instruction::MemorySize { dst });
        }
        MemoryGrow { mem, .. } => {
            if *mem != 0 {
                return Err(UnsupportedFeature::MultiMemory.into());
            }
            let pages = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::MemoryGrow { dst, pages });
        }
        MemoryFill { mem } => {
            if *mem != 0 {
                return Err(UnsupportedFeature::MultiMemory.into());
            }
            let len = t.pop()?;
            let val = t.pop()?;
            let dest = t.pop()?;
            t.emit(Instruction::MemoryFill { dest, val, len });
        }
        MemoryCopy { dst_mem, src_mem } => {
            if *dst_mem != 0 || *src_mem != 0 {
                return Err(UnsupportedFeature::MultiMemory.into());
            }
            let len = t.pop()?;
            let src = t.pop()?;
            let dest = t.pop()?;
            t.emit(Instruction::MemoryCopy { dest, src, len });
        }
        MemoryInit { data_index, mem } => {
            if *mem != 0 {
                return Err(UnsupportedFeature::MultiMemory.into());
            }
            let len = t.pop()?;
            let src_offset = t.pop()?;
            let dest = t.pop()?;
            t.emit(Instruction::MemoryInit {
                data_idx: *data_index,
                dest,
                src_offset,
                len,
            });
        }
        DataDrop { data_index } => {
            t.emit(Instruction::DataDrop {
                data_idx: *data_index,
            });
        }

        // === Constants ===
        I32Const { value } => {
            let dst = t.push();
            t.emit(Instruction::I32Const { dst, val: *value });
        }
        I64Const { value } => {
            let dst = t.push();
            t.emit(Instruction::I64Const { dst, val: *value });
        }
        F32Const { value } => {
            let dst = t.push();
            t.emit(Instruction::F32Const {
                dst,
                val: value.bits(),
            });
        }
        F64Const { value } => {
            let dst = t.push();
            t.emit(Instruction::F64Const {
                dst,
                val: value.bits(),
            });
        }

        // === References ===
        RefNull { hty } => {
            let ref_type = parse_heap_type(hty)?;
            let dst = t.push();
            t.emit(Instruction::RefNull { dst, ty: ref_type });
        }
        RefIsNull => {
            let src = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::RefIsNull { dst, src });
        }
        RefFunc { function_index } => {
            let dst = t.push();
            t.emit(Instruction::RefFunc {
                dst,
                func_idx: *function_index,
            });
        }

        // === Arithmetic (unary) ===
        I32Eqz => t.unary_op(UnaryOp::I32Eqz)?,
        I64Eqz => t.unary_op(UnaryOp::I64Eqz)?,
        I32Clz => t.unary_op(UnaryOp::I32Clz)?,
        I32Ctz => t.unary_op(UnaryOp::I32Ctz)?,
        I32Popcnt => t.unary_op(UnaryOp::I32Popcnt)?,
        I64Clz => t.unary_op(UnaryOp::I64Clz)?,
        I64Ctz => t.unary_op(UnaryOp::I64Ctz)?,
        I64Popcnt => t.unary_op(UnaryOp::I64Popcnt)?,
        I32WrapI64 => t.unary_op(UnaryOp::I32WrapI64)?,
        I64ExtendI32S => t.unary_op(UnaryOp::I64ExtendI32S)?,
        I64ExtendI32U => t.unary_op(UnaryOp::I64ExtendI32U)?,
        I32Extend8S => t.unary_op(UnaryOp::I32Extend8S)?,
        I32Extend16S => t.unary_op(UnaryOp::I32Extend16S)?,
        I64Extend8S => t.unary_op(UnaryOp::I64Extend8S)?,
        I64Extend16S => t.unary_op(UnaryOp::I64Extend16S)?,
        I64Extend32S => t.unary_op(UnaryOp::I64Extend32S)?,
        F32Abs => t.unary_op(UnaryOp::F32Abs)?,
        F32Neg => t.unary_op(UnaryOp::F32Neg)?,
        F32Ceil => t.unary_op(UnaryOp::F32Ceil)?,
        F32Floor => t.unary_op(UnaryOp::F32Floor)?,
        F32Trunc => t.unary_op(UnaryOp::F32Trunc)?,
        F32Nearest => t.unary_op(UnaryOp::F32Nearest)?,
        F32Sqrt => t.unary_op(UnaryOp::F32Sqrt)?,
        F64Abs => t.unary_op(UnaryOp::F64Abs)?,
        F64Neg => t.unary_op(UnaryOp::F64Neg)?,
        F64Ceil => t.unary_op(UnaryOp::F64Ceil)?,
        F64Floor => t.unary_op(UnaryOp::F64Floor)?,
        F64Trunc => t.unary_op(UnaryOp::F64Trunc)?,
        F64Nearest => t.unary_op(UnaryOp::F64Nearest)?,
        F64Sqrt => t.unary_op(UnaryOp::F64Sqrt)?,
        I32TruncF32S => t.unary_op(UnaryOp::I32TruncF32S)?,
        I32TruncF32U => t.unary_op(UnaryOp::I32TruncF32U)?,
        I32TruncF64S => t.unary_op(UnaryOp::I32TruncF64S)?,
        I32TruncF64U => t.unary_op(UnaryOp::I32TruncF64U)?,
        I64TruncF32S => t.unary_op(UnaryOp::I64TruncF32S)?,
        I64TruncF32U => t.unary_op(UnaryOp::I64TruncF32U)?,
        I64TruncF64S => t.unary_op(UnaryOp::I64TruncF64S)?,
        I64TruncF64U => t.unary_op(UnaryOp::I64TruncF64U)?,
        F32ConvertI32S => t.unary_op(UnaryOp::F32ConvertI32S)?,
        F32ConvertI32U => t.unary_op(UnaryOp::F32ConvertI32U)?,
        F32ConvertI64S => t.unary_op(UnaryOp::F32ConvertI64S)?,
        F32ConvertI64U => t.unary_op(UnaryOp::F32ConvertI64U)?,
        F64ConvertI32S => t.unary_op(UnaryOp::F64ConvertI32S)?,
        F64ConvertI32U => t.unary_op(UnaryOp::F64ConvertI32U)?,
        F64ConvertI64S => t.unary_op(UnaryOp::F64ConvertI64S)?,
        F64ConvertI64U => t.unary_op(UnaryOp::F64ConvertI64U)?,
        F32DemoteF64 => t.unary_op(UnaryOp::F32DemoteF64)?,
        F64PromoteF32 => t.unary_op(UnaryOp::F64PromoteF32)?,
        I32ReinterpretF32 => t.unary_op(UnaryOp::I32ReinterpretF32)?,
        I64ReinterpretF64 => t.unary_op(UnaryOp::I64ReinterpretF64)?,
        F32ReinterpretI32 => t.unary_op(UnaryOp::F32ReinterpretI32)?,
        F64ReinterpretI64 => t.unary_op(UnaryOp::F64ReinterpretI64)?,
        I32TruncSatF32S => t.unary_op(UnaryOp::I32TruncSatF32S)?,
        I32TruncSatF32U => t.unary_op(UnaryOp::I32TruncSatF32U)?,
        I32TruncSatF64S => t.unary_op(UnaryOp::I32TruncSatF64S)?,
        I32TruncSatF64U => t.unary_op(UnaryOp::I32TruncSatF64U)?,
        I64TruncSatF32S => t.unary_op(UnaryOp::I64TruncSatF32S)?,
        I64TruncSatF32U => t.unary_op(UnaryOp::I64TruncSatF32U)?,
        I64TruncSatF64S => t.unary_op(UnaryOp::I64TruncSatF64S)?,
        I64TruncSatF64U => t.unary_op(UnaryOp::I64TruncSatF64U)?,

        // === Arithmetic (binary) ===
        I32Eq => t.binary_op(BinaryOp::I32Eq)?,
        I32Ne => t.binary_op(BinaryOp::I32Ne)?,
        I32LtS => t.binary_op(BinaryOp::I32LtS)?,
        I32LtU => t.binary_op(BinaryOp::I32LtU)?,
        I32GtS => t.binary_op(BinaryOp::I32GtS)?,
        I32GtU => t.binary_op(BinaryOp::I32GtU)?,
        I32LeS => t.binary_op(BinaryOp::I32LeS)?,
        I32LeU => t.binary_op(BinaryOp::I32LeU)?,
        I32GeS => t.binary_op(BinaryOp::I32GeS)?,
        I32GeU => t.binary_op(BinaryOp::I32GeU)?,
        I64Eq => t.binary_op(BinaryOp::I64Eq)?,
        I64Ne => t.binary_op(BinaryOp::I64Ne)?,
        I64LtS => t.binary_op(BinaryOp::I64LtS)?,
        I64LtU => t.binary_op(BinaryOp::I64LtU)?,
        I64GtS => t.binary_op(BinaryOp::I64GtS)?,
        I64GtU => t.binary_op(BinaryOp::I64GtU)?,
        I64LeS => t.binary_op(BinaryOp::I64LeS)?,
        I64LeU => t.binary_op(BinaryOp::I64LeU)?,
        I64GeS => t.binary_op(BinaryOp::I64GeS)?,
        I64GeU => t.binary_op(BinaryOp::I64GeU)?,
        I32Add => t.binary_op(BinaryOp::I32Add)?,
        I32Sub => t.binary_op(BinaryOp::I32Sub)?,
        I32Mul => t.binary_op(BinaryOp::I32Mul)?,
        I32DivS => t.binary_op(BinaryOp::I32DivS)?,
        I32DivU => t.binary_op(BinaryOp::I32DivU)?,
        I32RemS => t.binary_op(BinaryOp::I32RemS)?,
        I32RemU => t.binary_op(BinaryOp::I32RemU)?,
        I32And => t.binary_op(BinaryOp::I32And)?,
        I32Or => t.binary_op(BinaryOp::I32Or)?,
        I32Xor => t.binary_op(BinaryOp::I32Xor)?,
        I32Shl => t.binary_op(BinaryOp::I32Shl)?,
        I32ShrS => t.binary_op(BinaryOp::I32ShrS)?,
        I32ShrU => t.binary_op(BinaryOp::I32ShrU)?,
        I32Rotl => t.binary_op(BinaryOp::I32Rotl)?,
        I32Rotr => t.binary_op(BinaryOp::I32Rotr)?,
        I64Add => t.binary_op(BinaryOp::I64Add)?,
        I64Sub => t.binary_op(BinaryOp::I64Sub)?,
        I64Mul => t.binary_op(BinaryOp::I64Mul)?,
        I64DivS => t.binary_op(BinaryOp::I64DivS)?,
        I64DivU => t.binary_op(BinaryOp::I64DivU)?,
        I64RemS => t.binary_op(BinaryOp::I64RemS)?,
        I64RemU => t.binary_op(BinaryOp::I64RemU)?,
        I64And => t.binary_op(BinaryOp::I64And)?,
        I64Or => t.binary_op(BinaryOp::I64Or)?,
        I64Xor => t.binary_op(BinaryOp::I64Xor)?,
        I64Shl => t.binary_op(BinaryOp::I64Shl)?,
        I64ShrS => t.binary_op(BinaryOp::I64ShrS)?,
        I64ShrU => t.binary_op(BinaryOp::I64ShrU)?,
        I64Rotl => t.binary_op(BinaryOp::I64Rotl)?,
        I64Rotr => t.binary_op(BinaryOp::I64Rotr)?,
        F32Eq => t.binary_op(BinaryOp::F32Eq)?,
        F32Ne => t.binary_op(BinaryOp::F32Ne)?,
        F32Lt => t.binary_op(BinaryOp::F32Lt)?,
        F32Gt => t.binary_op(BinaryOp::F32Gt)?,
        F32Le => t.binary_op(BinaryOp::F32Le)?,
        F32Ge => t.binary_op(BinaryOp::F32Ge)?,
        F64Eq => t.binary_op(BinaryOp::F64Eq)?,
        F64Ne => t.binary_op(BinaryOp::F64Ne)?,
        F64Lt => t.binary_op(BinaryOp::F64Lt)?,
        F64Gt => t.binary_op(BinaryOp::F64Gt)?,
        F64Le => t.binary_op(BinaryOp::F64Le)?,
        F64Ge => t.binary_op(BinaryOp::F64Ge)?,
        F32Add => t.binary_op(BinaryOp::F32Add)?,
        F32Sub => t.binary_op(BinaryOp::F32Sub)?,
        F32Mul => t.binary_op(BinaryOp::F32Mul)?,
        F32Div => t.binary_op(BinaryOp::F32Div)?,
        F32Min => t.binary_op(BinaryOp::F32Min)?,
        F32Max => t.binary_op(BinaryOp::F32Max)?,
        F32Copysign => t.binary_op(BinaryOp::F32Copysign)?,
        F64Add => t.binary_op(BinaryOp::F64Add)?,
        F64Sub => t.binary_op(BinaryOp::F64Sub)?,
        F64Mul => t.binary_op(BinaryOp::F64Mul)?,
        F64Div => t.binary_op(BinaryOp::F64Div)?,
        F64Min => t.binary_op(BinaryOp::F64Min)?,
        F64Max => t.binary_op(BinaryOp::F64Max)?,
        F64Copysign => t.binary_op(BinaryOp::F64Copysign)?,

        _ => {
            return Err(UnsupportedFeature::Opcode(format!("{:?}", op)).into());
        }
    }

    Ok(())
}

fn block_type_result_arity(blockty: &WasmBlockType, all_types: &[FuncType]) -> Result<usize> {
    match blockty {
        WasmBlockType::Empty => Ok(0),
        WasmBlockType::Type(_) => Ok(1),
        WasmBlockType::FuncType(idx) => all_types
            .get(*idx as usize)
            .map(|ty| ty.results.len())
            .ok_or(Error::Validation(ValidationError::UnknownType(*idx))),
    }
}

fn parse_memarg(memarg: &wasmparser::MemArg) -> MemArg {
    MemArg {
        align: memarg.align as u32,
        offset: memarg.offset as u32,
    }
}

fn emit_load(t: &mut Translator, kind: LoadKind, memarg: &wasmparser::MemArg) -> Result<()> {
    let addr = t.pop()?;
    let dst = t.push();
    t.emit(Instruction::Load {
        kind,
        dst,
        addr,
        memarg: parse_memarg(memarg),
    });
    Ok(())
}

fn emit_store(t: &mut Translator, kind: StoreKind, memarg: &wasmparser::MemArg) -> Result<()> {
    let val = t.pop()?;
    let addr = t.pop()?;
    t.emit(Instruction::Store {
        kind,
        addr,
        val,
        memarg: parse_memarg(memarg),
    });
    Ok(())
}
