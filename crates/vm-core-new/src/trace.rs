//! Symbolic execution trace.

use std::collections::HashSet;

use ir::{Instruction, ValType};

use crate::value::Value;

/// Input parameter for a traced function.
#[derive(Debug, Clone, Copy)]
pub enum TraceInput {
    /// Private value - we have the actual value, peer needs it.
    Private(Value),
    /// Blind value - we don't have it, peer will provide it.
    Blind(ValType),
}

#[derive(Debug, Default, Clone)]
pub struct Trace {
    trace: Vec<Instruction>,
}

impl Trace {
    /// Returns the instructions in the trace.
    pub fn instructions(&self) -> &[Instruction] {
        &self.trace
    }
}

#[derive(Debug, Default)]
pub(crate) struct TraceBuilder {
    inputs: Vec<TraceInput>,
    trace: Vec<Instruction>,
    scratch: Vec<Instruction>,
}

impl TraceBuilder {
    /// Creates a new trace builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes an instruction.
    pub fn push_instr(&mut self, instr: Instruction) {
        self.trace.push(instr);
    }

    /// Inserts a const at `depth` of the stack.
    ///
    /// `depth=0` means top of stack (append).
    /// `depth=1` means under the top value.
    pub fn insert_const(&mut self, depth: usize, value: Value) {
        let const_instr = value.into_const();

        if depth == 0 {
            self.trace.push(const_instr);
            return;
        }

        let mut remaining = depth;
        for (idx, instr) in self.trace.iter().enumerate().rev() {
            let output = instr.output_arity();
            let input = instr.input_arity();

            if output > input {
                let net = output - input;
                if net >= remaining {
                    self.trace.insert(idx, const_instr);
                    return;
                }
                remaining -= net;
            } else if input > output {
                remaining += input - output;
            }
        }

        self.trace.insert(0, const_instr);
    }

    pub fn fold(&mut self, instr: &Instruction, result: Value) {
        // Identify which previous instructions produced the operands
        // for this instruction and remove them, while inserting a Const
        // for the output value.
        let mut count = instr.input_arity();
        let mut remove = HashSet::new();
        let mut start_idx = self.trace.len();

        for idx in (0..self.trace.len()).rev() {
            if count == 0 {
                break;
            }

            let trace_instr = &self.trace[idx];
            let output_arity = trace_instr.output_arity();
            if output_arity > 0 {
                count -= output_arity;
                count += trace_instr.input_arity();
                remove.insert(idx);
                start_idx = idx;
            } else {
                // Track start even for interleaved zero-output instructions
                start_idx = idx;
            }
        }

        // Rebuild from start_idx, keeping non-removed and converting LocalTee
        self.scratch.clear();
        for idx in start_idx..self.trace.len() {
            let trace_instr = &self.trace[idx];
            if remove.contains(&idx) {
                if let Instruction::LocalTee(addr) = trace_instr {
                    // Preserve side-effect by converting to LocalSet
                    self.scratch.push(Instruction::LocalSet(*addr));
                }
                // else: removed entirely
            } else {
                self.scratch.push(trace_instr.clone());
            }
        }

        self.trace.truncate(start_idx);
        self.trace.extend_from_slice(&self.scratch);
        self.scratch.clear();

        self.trace.push(result.into_const());
    }

    /// Removes symbolic operands from the trace.
    ///
    /// Removes `symbolic_count` values from the trace stack. Used when an
    /// operation with symbolic operands produces a constant result
    /// (e.g., `x * 0 = 0`). The constant result is NOT added to the trace
    /// since it will be returned directly as a clear value.
    pub fn fold_to_const(&mut self, symbolic_count: usize) {
        if symbolic_count == 0 {
            return;
        }

        let mut count = symbolic_count;
        let mut remove = HashSet::new();
        let mut start_idx = self.trace.len();

        for idx in (0..self.trace.len()).rev() {
            if count == 0 {
                break;
            }

            let trace_instr = &self.trace[idx];
            let output_arity = trace_instr.output_arity();
            if output_arity > 0 {
                count -= output_arity;
                count += trace_instr.input_arity();
                remove.insert(idx);
                start_idx = idx;
            } else {
                start_idx = idx;
            }
        }

        // Rebuild from start_idx, keeping non-removed and converting LocalTee
        self.scratch.clear();
        for idx in start_idx..self.trace.len() {
            let trace_instr = &self.trace[idx];
            if remove.contains(&idx) {
                if let Instruction::LocalTee(addr) = trace_instr {
                    self.scratch.push(Instruction::LocalSet(*addr));
                }
            } else {
                self.scratch.push(trace_instr.clone());
            }
        }

        self.trace.truncate(start_idx);
        self.trace.extend_from_slice(&self.scratch);
        self.scratch.clear();
    }

    /// Folds an identity operation, keeping only the identity operand.
    ///
    /// For operations like `x + 0 = x` or `x * 1 = x`, we remove the
    /// instructions that produced the non-identity operand while keeping
    /// the ones that produced the identity operand.
    pub fn fold_identity(&mut self, instr: &Instruction, identity_idx: usize) {
        let input_arity = instr.input_arity();
        if input_arity == 0 {
            return;
        }

        // Find operand ranges by walking backwards
        // For binary ops: operand 0 is deeper in stack, operand 1 is top
        let mut operand_indices: Vec<Vec<usize>> = vec![Vec::new(); input_arity];
        let mut operand_counts: Vec<usize> = vec![1; input_arity];
        let mut current_operand = input_arity - 1;
        let mut start_idx = self.trace.len();

        for idx in (0..self.trace.len()).rev() {
            if operand_counts.iter().all(|&c| c == 0) {
                break;
            }

            let trace_instr = &self.trace[idx];
            let output_arity = trace_instr.output_arity();

            if output_arity > 0 && operand_counts[current_operand] > 0 {
                operand_counts[current_operand] -= output_arity;
                operand_counts[current_operand] += trace_instr.input_arity();
                operand_indices[current_operand].push(idx);
                start_idx = idx;

                // Move to previous operand when current is complete
                if operand_counts[current_operand] == 0 && current_operand > 0 {
                    current_operand -= 1;
                }
            } else if output_arity == 0 {
                start_idx = idx;
            }
        }

        // Collect indices to remove (all non-identity operands)
        let mut remove = HashSet::new();
        for (i, indices) in operand_indices.iter().enumerate() {
            if i != identity_idx {
                for &idx in indices {
                    remove.insert(idx);
                }
            }
        }

        // Rebuild, keeping identity operand and side effects
        self.scratch.clear();
        for idx in start_idx..self.trace.len() {
            let trace_instr = &self.trace[idx];
            if remove.contains(&idx) {
                if let Instruction::LocalTee(addr) = trace_instr {
                    self.scratch.push(Instruction::LocalSet(*addr));
                }
            } else {
                self.scratch.push(trace_instr.clone());
            }
        }

        self.trace.truncate(start_idx);
        self.trace.extend_from_slice(&self.scratch);
        self.scratch.clear();
    }

    /// Builds a trace.
    pub fn build(&mut self) -> Option<Trace> {
        if !self.trace.is_empty() {
            Some(Trace {
                trace: std::mem::take(&mut self.trace),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::InstructionArith;

    #[test]
    fn fold_simple_binary() {
        // trace: [I32Const(2), I32Const(3)]
        // fold(I32Add, 5)
        // result: [I32Const(5)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(2));
        builder.push_instr(Instruction::I32Const(3));

        builder.fold(&Instruction::Arith(InstructionArith::I32Add), Value::I32(5));

        assert_eq!(builder.trace, vec![Instruction::I32Const(5)]);
    }

    #[test]
    fn fold_preserves_earlier_instructions() {
        // trace: [I32Const(100), I32Const(2), I32Const(3)]
        // fold(I32Add, 5)
        // result: [I32Const(100), I32Const(5)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(100));
        builder.push_instr(Instruction::I32Const(2));
        builder.push_instr(Instruction::I32Const(3));

        builder.fold(&Instruction::Arith(InstructionArith::I32Add), Value::I32(5));

        assert_eq!(
            builder.trace,
            vec![Instruction::I32Const(100), Instruction::I32Const(5)]
        );
    }

    #[test]
    fn fold_with_interleaved_local_set() {
        // trace: [I32Const(2), LocalSet(0), I32Const(3)]
        // fold(I32Add, 5)
        // LocalSet has output_arity=0, so it should be preserved
        // result: [LocalSet(0), I32Const(5)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(2));
        builder.push_instr(Instruction::LocalSet(0));
        builder.push_instr(Instruction::I32Const(3));

        builder.fold(&Instruction::Arith(InstructionArith::I32Add), Value::I32(5));

        assert_eq!(
            builder.trace,
            vec![Instruction::LocalSet(0), Instruction::I32Const(5)]
        );
    }

    #[test]
    fn fold_local_tee_converts_to_local_set() {
        // trace: [LocalGet(0), LocalTee(1)]
        // fold(I32Add, 0) with I32Const(0) as second operand (x * 0 = 0)
        // LocalTee produces a value, so it's part of the operand chain
        // But we preserve side effects by converting to LocalSet
        // result: [LocalSet(1), I32Const(0)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::LocalGet(0));
        builder.push_instr(Instruction::LocalTee(1));
        builder.push_instr(Instruction::I32Const(0));

        builder.fold(&Instruction::Arith(InstructionArith::I32Mul), Value::I32(0));

        assert_eq!(
            builder.trace,
            vec![Instruction::LocalSet(1), Instruction::I32Const(0)]
        );
    }

    #[test]
    fn fold_nested_operations() {
        // trace: [I32Const(1), I32Const(2), I32Add, I32Const(3)]
        // The I32Add consumed the first two consts, now we fold I32Mul
        // fold(I32Mul, 9)
        // result: [I32Const(9)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(1));
        builder.push_instr(Instruction::I32Const(2));
        builder.push_instr(Instruction::Arith(InstructionArith::I32Add));
        builder.push_instr(Instruction::I32Const(3));

        builder.fold(&Instruction::Arith(InstructionArith::I32Mul), Value::I32(9));

        assert_eq!(builder.trace, vec![Instruction::I32Const(9)]);
    }

    #[test]
    fn fold_with_multiple_interleaved_side_effects() {
        // trace: [I32Const(2), LocalSet(0), LocalSet(1), I32Const(3)]
        // fold(I32Add, 5)
        // Both LocalSets should be preserved
        // result: [LocalSet(0), LocalSet(1), I32Const(5)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(2));
        builder.push_instr(Instruction::LocalSet(0));
        builder.push_instr(Instruction::LocalSet(1));
        builder.push_instr(Instruction::I32Const(3));

        builder.fold(&Instruction::Arith(InstructionArith::I32Add), Value::I32(5));

        assert_eq!(
            builder.trace,
            vec![
                Instruction::LocalSet(0),
                Instruction::LocalSet(1),
                Instruction::I32Const(5)
            ]
        );
    }

    #[test]
    fn fold_unary_operation() {
        // trace: [I32Const(5)]
        // fold(I32Clz, 29)  // clz(5) = 29
        // result: [I32Const(29)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(5));

        builder.fold(
            &Instruction::Arith(InstructionArith::I32Clz),
            Value::I32(29),
        );

        assert_eq!(builder.trace, vec![Instruction::I32Const(29)]);
    }

    #[test]
    fn fold_with_local_get_chain() {
        // trace: [LocalGet(0), LocalGet(1)]
        // fold(I32Add, 10)
        // Both LocalGets produce values and should be removed
        // result: [I32Const(10)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::LocalGet(0));
        builder.push_instr(Instruction::LocalGet(1));

        builder.fold(
            &Instruction::Arith(InstructionArith::I32Add),
            Value::I32(10),
        );

        assert_eq!(builder.trace, vec![Instruction::I32Const(10)]);
    }

    #[test]
    fn insert_const_depth_zero() {
        // depth=0 appends to end (top of stack)
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(1));
        builder.insert_const(0, Value::I32(2));

        assert_eq!(
            builder.trace,
            vec![Instruction::I32Const(1), Instruction::I32Const(2)]
        );
    }

    #[test]
    fn insert_const_depth_one() {
        // depth=1 inserts under top value
        // trace: [I32Const(1)]
        // insert_const(1, 2)
        // result: [I32Const(2), I32Const(1)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(1));
        builder.insert_const(1, Value::I32(2));

        assert_eq!(
            builder.trace,
            vec![Instruction::I32Const(2), Instruction::I32Const(1)]
        );
    }

    #[test]
    fn insert_const_depth_one_after_binary() {
        // trace: [I32Const(1), I32Const(2), I32Add]
        // Stack after trace: [3] (one value)
        // insert_const(1, 99) should go before the entire binary op
        // result: [I32Const(99), I32Const(1), I32Const(2), I32Add]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(1));
        builder.push_instr(Instruction::I32Const(2));
        builder.push_instr(Instruction::Arith(InstructionArith::I32Add));
        builder.insert_const(1, Value::I32(99));

        assert_eq!(
            builder.trace,
            vec![
                Instruction::I32Const(99),
                Instruction::I32Const(1),
                Instruction::I32Const(2),
                Instruction::Arith(InstructionArith::I32Add),
            ]
        );
    }

    #[test]
    fn insert_const_depth_two() {
        // trace: [I32Const(1), I32Const(2)]
        // Stack: [1, 2] (2 on top)
        // insert_const(2, 99) should go at the beginning
        // result: [I32Const(99), I32Const(1), I32Const(2)]
        let mut builder = TraceBuilder::new();
        builder.push_instr(Instruction::I32Const(1));
        builder.push_instr(Instruction::I32Const(2));
        builder.insert_const(2, Value::I32(99));

        assert_eq!(
            builder.trace,
            vec![
                Instruction::I32Const(99),
                Instruction::I32Const(1),
                Instruction::I32Const(2),
            ]
        );
    }
}
