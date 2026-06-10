//! AND-gate + advice cost of each op, used by capture to budget chunks.
//!
//! Costs come from the `mpz_vm_circuits` gadgets' published `COST*` constants,
//! selecting the constant-specialized variant when an operand is public (the
//! same choice `replay` makes when emitting the circuit).

use mpz_vm_core::{Op, Operand};
use mpz_vm_ir::{BinaryOp, UnaryOp};

use mpz_vm_circuits as circ;

use crate::error::{Result, unsupported_binary, unsupported_op, unsupported_unary};

pub(crate) fn op_cost(op: &Op) -> Result<usize> {
    Ok(match op {
        Op::Copy { .. } | Op::GlobalGet { .. } | Op::GlobalSet { .. } => 0,
        Op::Load { kind, .. } if !kind.is_float() => 0,
        Op::Store { kind, .. } if !kind.is_float() => 0,
        Op::Binary {
            op: bop, lhs, rhs, ..
        } => binary_cost(*bop, lhs, rhs)?,
        Op::Unary { op: uop, .. } => unary_cost(*uop)?,
        _ => return Err(unsupported_op(op)),
    })
}

fn binary_cost(op: BinaryOp, lhs: &Operand, rhs: &Operand) -> Result<usize> {
    use BinaryOp::*;
    Ok(match op {
        // Comparisons are always symbolic.
        I32Eq => circ::I32Eq::COST,
        I32Ne => circ::I32Ne::COST,
        I32LtS => circ::I32LtS::COST,
        I32LtU => circ::I32LtU::COST,
        I32GtS => circ::I32GtS::COST,
        I32GtU => circ::I32GtU::COST,
        I32LeS => circ::I32LeS::COST,
        I32LeU => circ::I32LeU::COST,
        I32GeS => circ::I32GeS::COST,
        I32GeU => circ::I32GeU::COST,
        I64Eq => circ::I64Eq::COST,
        I64Ne => circ::I64Ne::COST,
        I64LtS => circ::I64LtS::COST,
        I64LtU => circ::I64LtU::COST,
        I64GtS => circ::I64GtS::COST,
        I64GtU => circ::I64GtU::COST,
        I64LeS => circ::I64LeS::COST,
        I64LeU => circ::I64LeU::COST,
        I64GeS => circ::I64GeS::COST,
        I64GeU => circ::I64GeU::COST,
        // Arithmetic. Multiply by a public constant uses the cheaper circuit.
        I32Add => circ::I32Add::COST,
        I32Sub => circ::I32Sub::COST,
        I32Mul if lhs.is_concrete() | rhs.is_concrete() => circ::I32Mul::COST_CONST,
        I32Mul => circ::I32Mul::COST,
        I64Add => circ::I64Add::COST,
        I64Sub => circ::I64Sub::COST,
        I64Mul if lhs.is_concrete() | rhs.is_concrete() => circ::I64Mul::COST_CONST,
        I64Mul => circ::I64Mul::COST,
        // Bitwise. `and`/`or` with a public constant use the cheaper circuit;
        // `xor` is always a free wire shuffle.
        I32And if lhs.is_concrete() | rhs.is_concrete() => circ::I32And::COST_CONST,
        I32And => circ::I32And::COST,
        I32Or if lhs.is_concrete() | rhs.is_concrete() => circ::I32Or::COST_CONST,
        I32Or => circ::I32Or::COST,
        I32Xor => circ::I32Xor::COST,
        I64And if lhs.is_concrete() | rhs.is_concrete() => circ::I64And::COST_CONST,
        I64And => circ::I64And::COST,
        I64Or if lhs.is_concrete() | rhs.is_concrete() => circ::I64Or::COST_CONST,
        I64Or => circ::I64Or::COST,
        I64Xor => circ::I64Xor::COST,
        // Shifts/rotates by a public constant amount are free wire shuffles.
        I32Shl if rhs.is_concrete() => circ::I32Shl::COST_CONST_AMOUNT,
        I32Shl => circ::I32Shl::COST,
        I32ShrS if rhs.is_concrete() => circ::I32ShrS::COST_CONST_AMOUNT,
        I32ShrS => circ::I32ShrS::COST,
        I32ShrU if rhs.is_concrete() => circ::I32ShrU::COST_CONST_AMOUNT,
        I32ShrU => circ::I32ShrU::COST,
        I32Rotl if rhs.is_concrete() => circ::I32Rotl::COST_CONST_AMOUNT,
        I32Rotl => circ::I32Rotl::COST,
        I32Rotr if rhs.is_concrete() => circ::I32Rotr::COST_CONST_AMOUNT,
        I32Rotr => circ::I32Rotr::COST,
        I64Shl if rhs.is_concrete() => circ::I64Shl::COST_CONST_AMOUNT,
        I64Shl => circ::I64Shl::COST,
        I64ShrS if rhs.is_concrete() => circ::I64ShrS::COST_CONST_AMOUNT,
        I64ShrS => circ::I64ShrS::COST,
        I64ShrU if rhs.is_concrete() => circ::I64ShrU::COST_CONST_AMOUNT,
        I64ShrU => circ::I64ShrU::COST,
        I64Rotl if rhs.is_concrete() => circ::I64Rotl::COST_CONST_AMOUNT,
        I64Rotl => circ::I64Rotl::COST,
        I64Rotr if rhs.is_concrete() => circ::I64Rotr::COST_CONST_AMOUNT,
        I64Rotr => circ::I64Rotr::COST,
        // Division/remainder by a public constant divisor skips the advice
        // entirely; otherwise `COST_WITH_ADVICE` already accounts for the
        // committed advice.
        I32DivU if rhs.is_concrete() => circ::I32DivU::COST_CONST_DIVISOR,
        I32DivU => circ::I32DivU::COST_WITH_ADVICE,
        I32RemU if rhs.is_concrete() => circ::I32RemU::COST_CONST_DIVISOR,
        I32RemU => circ::I32RemU::COST_WITH_ADVICE,
        I32DivS if rhs.is_concrete() => circ::I32DivS::COST_CONST_DIVISOR,
        I32DivS => circ::I32DivS::COST_WITH_ADVICE,
        I32RemS if rhs.is_concrete() => circ::I32RemS::COST_CONST_DIVISOR,
        I32RemS => circ::I32RemS::COST_WITH_ADVICE,
        I64DivU if rhs.is_concrete() => circ::I64DivU::COST_CONST_DIVISOR,
        I64DivU => circ::I64DivU::COST_WITH_ADVICE,
        I64RemU if rhs.is_concrete() => circ::I64RemU::COST_CONST_DIVISOR,
        I64RemU => circ::I64RemU::COST_WITH_ADVICE,
        I64DivS if rhs.is_concrete() => circ::I64DivS::COST_CONST_DIVISOR,
        I64DivS => circ::I64DivS::COST_WITH_ADVICE,
        I64RemS if rhs.is_concrete() => circ::I64RemS::COST_CONST_DIVISOR,
        I64RemS => circ::I64RemS::COST_WITH_ADVICE,
        _ => return unsupported_binary(op),
    })
}

fn unary_cost(op: UnaryOp) -> Result<usize> {
    use UnaryOp::*;
    Ok(match op {
        I32Eqz => circ::I32Eqz::COST,
        I64Eqz => circ::I64Eqz::COST,
        I32Clz => circ::I32Clz::COST_WITH_ADVICE,
        I32Ctz => circ::I32Ctz::COST_WITH_ADVICE,
        I32Popcnt => circ::I32Popcnt::COST,
        I64Clz => circ::I64Clz::COST_WITH_ADVICE,
        I64Ctz => circ::I64Ctz::COST_WITH_ADVICE,
        I64Popcnt => circ::I64Popcnt::COST,
        I32WrapI64 => circ::I32WrapI64::COST,
        I64ExtendI32S => circ::I64ExtendI32S::COST,
        I64ExtendI32U => circ::I64ExtendI32U::COST,
        I32Extend8S => circ::I32Extend8S::COST,
        I32Extend16S => circ::I32Extend16S::COST,
        I64Extend8S => circ::I64Extend8S::COST,
        I64Extend16S => circ::I64Extend16S::COST,
        I64Extend32S => circ::I64Extend32S::COST,
        _ => return unsupported_unary(op),
    })
}
