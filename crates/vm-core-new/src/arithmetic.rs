//! Clear arithmetic operations.

use ir::InstructionArith;

use crate::{Trap, Value, VmError};

/// Execute an arithmetic instruction on clear values.
pub fn execute(
    instr: &InstructionArith,
    operands: impl IntoIterator<Item = Value>,
) -> Result<Value, VmError> {
    use InstructionArith::*;

    let mut iter = operands.into_iter();
    let mut next = || {
        iter.next()
            .ok_or_else(|| VmError::Internal("missing operand".into()))
    };

    let output = match instr {
        // i32 Comparisons
        I32Eqz => i32_eqz(next()?.as_i32()?).into(),
        I32Eq => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_eq(a, b).into()
        }
        I32Ne => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_ne(a, b).into()
        }
        I32LtS => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_lt_s(a, b).into()
        }
        I32LtU => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_lt_u(a, b).into()
        }
        I32GtS => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_gt_s(a, b).into()
        }
        I32GtU => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_gt_u(a, b).into()
        }
        I32LeS => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_le_s(a, b).into()
        }
        I32LeU => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_le_u(a, b).into()
        }
        I32GeS => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_ge_s(a, b).into()
        }
        I32GeU => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_ge_u(a, b).into()
        }

        // i64 Comparisons
        I64Eqz => i64_eqz(next()?.as_i64()?).into(),
        I64Eq => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_eq(a, b).into()
        }
        I64Ne => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_ne(a, b).into()
        }
        I64LtS => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_lt_s(a, b).into()
        }
        I64LtU => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_lt_u(a, b).into()
        }
        I64GtS => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_gt_s(a, b).into()
        }
        I64GtU => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_gt_u(a, b).into()
        }
        I64LeS => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_le_s(a, b).into()
        }
        I64LeU => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_le_u(a, b).into()
        }
        I64GeS => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_ge_s(a, b).into()
        }
        I64GeU => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_ge_u(a, b).into()
        }

        // i32 Arithmetic
        I32Clz => i32_clz(next()?.as_i32()?).into(),
        I32Ctz => i32_ctz(next()?.as_i32()?).into(),
        I32Popcnt => i32_popcnt(next()?.as_i32()?).into(),
        I32Add => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_add(a, b).into()
        }
        I32Sub => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_sub(a, b).into()
        }
        I32Mul => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_mul(a, b).into()
        }
        I32DivS => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_div_s(a, b)?.into()
        }
        I32DivU => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_div_u(a, b)?.into()
        }
        I32RemS => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_rem_s(a, b)?.into()
        }
        I32RemU => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_rem_u(a, b)?.into()
        }
        I32And => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_and(a, b).into()
        }
        I32Or => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_or(a, b).into()
        }
        I32Xor => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_xor(a, b).into()
        }
        I32Shl => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_shl(a, b).into()
        }
        I32ShrS => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_shr_s(a, b).into()
        }
        I32ShrU => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_shr_u(a, b).into()
        }
        I32Rotl => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_rotl(a, b).into()
        }
        I32Rotr => {
            let b = next()?.as_i32()?;
            let a = next()?.as_i32()?;
            i32_rotr(a, b).into()
        }

        // i64 Arithmetic
        I64Clz => i64_clz(next()?.as_i64()?).into(),
        I64Ctz => i64_ctz(next()?.as_i64()?).into(),
        I64Popcnt => i64_popcnt(next()?.as_i64()?).into(),
        I64Add => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_add(a, b).into()
        }
        I64Sub => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_sub(a, b).into()
        }
        I64Mul => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_mul(a, b).into()
        }
        I64DivS => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_div_s(a, b)?.into()
        }
        I64DivU => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_div_u(a, b)?.into()
        }
        I64RemS => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_rem_s(a, b)?.into()
        }
        I64RemU => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_rem_u(a, b)?.into()
        }
        I64And => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_and(a, b).into()
        }
        I64Or => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_or(a, b).into()
        }
        I64Xor => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_xor(a, b).into()
        }
        I64Shl => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_shl(a, b).into()
        }
        I64ShrS => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_shr_s(a, b).into()
        }
        I64ShrU => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_shr_u(a, b).into()
        }
        I64Rotl => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_rotl(a, b).into()
        }
        I64Rotr => {
            let b = next()?.as_i64()?;
            let a = next()?.as_i64()?;
            i64_rotr(a, b).into()
        }

        // Conversion Instructions
        I32WrapI64 => i32_wrap_i64(next()?.as_i64()?).into(),
        I64ExtendI32S => i64_extend_i32_s(next()?.as_i32()?).into(),
        I64ExtendI32U => i64_extend_i32_u(next()?.as_i32()?).into(),
        I32Extend8S => i32_extend8_s(next()?.as_i32()?).into(),
        I32Extend16S => i32_extend16_s(next()?.as_i32()?).into(),
        I64Extend8S => i64_extend8_s(next()?.as_i64()?).into(),
        I64Extend16S => i64_extend16_s(next()?.as_i64()?).into(),
        I64Extend32S => i64_extend32_s(next()?.as_i64()?).into(),

        // f32 comparisons (return i32)
        F32Eq => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::I32((a == b) as i32)
        }
        F32Ne => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::I32((a != b) as i32)
        }
        F32Lt => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::I32((a < b) as i32)
        }
        F32Gt => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::I32((a > b) as i32)
        }
        F32Le => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::I32((a <= b) as i32)
        }
        F32Ge => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::I32((a >= b) as i32)
        }

        // f64 comparisons (return i32)
        F64Eq => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::I32((a == b) as i32)
        }
        F64Ne => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::I32((a != b) as i32)
        }
        F64Lt => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::I32((a < b) as i32)
        }
        F64Gt => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::I32((a > b) as i32)
        }
        F64Le => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::I32((a <= b) as i32)
        }
        F64Ge => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::I32((a >= b) as i32)
        }

        // f32 unary arithmetic
        F32Abs => Value::F32(next()?.as_f32()?.abs()),
        F32Neg => Value::F32(-next()?.as_f32()?),
        F32Ceil => Value::F32(next()?.as_f32()?.ceil()),
        F32Floor => Value::F32(next()?.as_f32()?.floor()),
        F32Trunc => Value::F32(next()?.as_f32()?.trunc()),
        F32Nearest => Value::F32(f32_nearest(next()?.as_f32()?)),
        F32Sqrt => Value::F32(next()?.as_f32()?.sqrt()),

        // f32 binary arithmetic
        F32Add => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::F32(a + b)
        }
        F32Sub => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::F32(a - b)
        }
        F32Mul => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::F32(a * b)
        }
        F32Div => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::F32(a / b)
        }
        F32Min => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::F32(f32_min(a, b))
        }
        F32Max => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::F32(f32_max(a, b))
        }
        F32Copysign => {
            let b = next()?.as_f32()?;
            let a = next()?.as_f32()?;
            Value::F32(a.copysign(b))
        }

        // f64 unary arithmetic
        F64Abs => Value::F64(next()?.as_f64()?.abs()),
        F64Neg => Value::F64(-next()?.as_f64()?),
        F64Ceil => Value::F64(next()?.as_f64()?.ceil()),
        F64Floor => Value::F64(next()?.as_f64()?.floor()),
        F64Trunc => Value::F64(next()?.as_f64()?.trunc()),
        F64Nearest => Value::F64(f64_nearest(next()?.as_f64()?)),
        F64Sqrt => Value::F64(next()?.as_f64()?.sqrt()),

        // f64 binary arithmetic
        F64Add => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::F64(a + b)
        }
        F64Sub => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::F64(a - b)
        }
        F64Mul => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::F64(a * b)
        }
        F64Div => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::F64(a / b)
        }
        F64Min => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::F64(f64_min(a, b))
        }
        F64Max => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::F64(f64_max(a, b))
        }
        F64Copysign => {
            let b = next()?.as_f64()?;
            let a = next()?.as_f64()?;
            Value::F64(a.copysign(b))
        }

        // Conversions: trunc float to int (trapping)
        I32TruncF32S => {
            let v = next()?.as_f32()?;
            Value::I32(i32_trunc_f32_s(v)?)
        }
        I32TruncF32U => {
            let v = next()?.as_f32()?;
            Value::I32(i32_trunc_f32_u(v)?)
        }
        I32TruncF64S => {
            let v = next()?.as_f64()?;
            Value::I32(i32_trunc_f64_s(v)?)
        }
        I32TruncF64U => {
            let v = next()?.as_f64()?;
            Value::I32(i32_trunc_f64_u(v)?)
        }
        I64TruncF32S => {
            let v = next()?.as_f32()?;
            Value::I64(i64_trunc_f32_s(v)?)
        }
        I64TruncF32U => {
            let v = next()?.as_f32()?;
            Value::I64(i64_trunc_f32_u(v)?)
        }
        I64TruncF64S => {
            let v = next()?.as_f64()?;
            Value::I64(i64_trunc_f64_s(v)?)
        }
        I64TruncF64U => {
            let v = next()?.as_f64()?;
            Value::I64(i64_trunc_f64_u(v)?)
        }

        // Conversions: int to float
        F32ConvertI32S => Value::F32(next()?.as_i32()? as f32),
        F32ConvertI32U => Value::F32((next()?.as_i32()? as u32) as f32),
        F32ConvertI64S => Value::F32(next()?.as_i64()? as f32),
        F32ConvertI64U => Value::F32((next()?.as_i64()? as u64) as f32),
        F64ConvertI32S => Value::F64(next()?.as_i32()? as f64),
        F64ConvertI32U => Value::F64((next()?.as_i32()? as u32) as f64),
        F64ConvertI64S => Value::F64(next()?.as_i64()? as f64),
        F64ConvertI64U => Value::F64((next()?.as_i64()? as u64) as f64),

        // Conversions: float to float
        F32DemoteF64 => Value::F32(next()?.as_f64()? as f32),
        F64PromoteF32 => Value::F64(next()?.as_f32()? as f64),

        // Reinterpret (bit cast)
        I32ReinterpretF32 => Value::I32(next()?.as_f32()?.to_bits() as i32),
        I64ReinterpretF64 => Value::I64(next()?.as_f64()?.to_bits() as i64),
        F32ReinterpretI32 => Value::F32(f32::from_bits(next()?.as_i32()? as u32)),
        F64ReinterpretI64 => Value::F64(f64::from_bits(next()?.as_i64()? as u64)),

        // Saturating truncations
        I32TruncSatF32S => Value::I32(i32_trunc_sat_f32_s(next()?.as_f32()?)),
        I32TruncSatF32U => Value::I32(i32_trunc_sat_f32_u(next()?.as_f32()?)),
        I32TruncSatF64S => Value::I32(i32_trunc_sat_f64_s(next()?.as_f64()?)),
        I32TruncSatF64U => Value::I32(i32_trunc_sat_f64_u(next()?.as_f64()?)),
        I64TruncSatF32S => Value::I64(i64_trunc_sat_f32_s(next()?.as_f32()?)),
        I64TruncSatF32U => Value::I64(i64_trunc_sat_f32_u(next()?.as_f32()?)),
        I64TruncSatF64S => Value::I64(i64_trunc_sat_f64_s(next()?.as_f64()?)),
        I64TruncSatF64U => Value::I64(i64_trunc_sat_f64_u(next()?.as_f64()?)),
    };

    Ok(output)
}

// i32 Comparisons
pub fn i32_eqz(v: i32) -> i32 {
    (v == 0) as i32
}

pub fn i32_eq(a: i32, b: i32) -> i32 {
    (a == b) as i32
}

pub fn i32_ne(a: i32, b: i32) -> i32 {
    (a != b) as i32
}

pub fn i32_lt_s(a: i32, b: i32) -> i32 {
    (a < b) as i32
}

pub fn i32_lt_u(a: i32, b: i32) -> i32 {
    ((a as u32) < (b as u32)) as i32
}

pub fn i32_gt_s(a: i32, b: i32) -> i32 {
    (a > b) as i32
}

pub fn i32_gt_u(a: i32, b: i32) -> i32 {
    ((a as u32) > (b as u32)) as i32
}

pub fn i32_le_s(a: i32, b: i32) -> i32 {
    (a <= b) as i32
}

pub fn i32_le_u(a: i32, b: i32) -> i32 {
    ((a as u32) <= (b as u32)) as i32
}

pub fn i32_ge_s(a: i32, b: i32) -> i32 {
    (a >= b) as i32
}

pub fn i32_ge_u(a: i32, b: i32) -> i32 {
    ((a as u32) >= (b as u32)) as i32
}

// i64 Comparisons
pub fn i64_eqz(v: i64) -> i32 {
    (v == 0) as i32
}

pub fn i64_eq(a: i64, b: i64) -> i32 {
    (a == b) as i32
}

pub fn i64_ne(a: i64, b: i64) -> i32 {
    (a != b) as i32
}

pub fn i64_lt_s(a: i64, b: i64) -> i32 {
    (a < b) as i32
}

pub fn i64_lt_u(a: i64, b: i64) -> i32 {
    ((a as u64) < (b as u64)) as i32
}

pub fn i64_gt_s(a: i64, b: i64) -> i32 {
    (a > b) as i32
}

pub fn i64_gt_u(a: i64, b: i64) -> i32 {
    ((a as u64) > (b as u64)) as i32
}

pub fn i64_le_s(a: i64, b: i64) -> i32 {
    (a <= b) as i32
}

pub fn i64_le_u(a: i64, b: i64) -> i32 {
    ((a as u64) <= (b as u64)) as i32
}

pub fn i64_ge_s(a: i64, b: i64) -> i32 {
    (a >= b) as i32
}

pub fn i64_ge_u(a: i64, b: i64) -> i32 {
    ((a as u64) >= (b as u64)) as i32
}

// i32 Arithmetic
pub fn i32_clz(v: i32) -> i32 {
    v.leading_zeros() as i32
}

pub fn i32_ctz(v: i32) -> i32 {
    v.trailing_zeros() as i32
}

pub fn i32_popcnt(v: i32) -> i32 {
    v.count_ones() as i32
}

pub fn i32_add(a: i32, b: i32) -> i32 {
    a.wrapping_add(b)
}

pub fn i32_sub(a: i32, b: i32) -> i32 {
    a.wrapping_sub(b)
}

pub fn i32_mul(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b)
}

pub fn i32_div_s(a: i32, b: i32) -> Result<i32, Trap> {
    if b == 0 {
        return Err(Trap::DivideByZero);
    }
    if a == i32::MIN && b == -1 {
        return Err(Trap::IntegerOverflow);
    }
    Ok(a / b)
}

pub fn i32_div_u(a: i32, b: i32) -> Result<i32, Trap> {
    if b == 0 {
        return Err(Trap::DivideByZero);
    }
    Ok(((a as u32) / (b as u32)) as i32)
}

pub fn i32_rem_s(a: i32, b: i32) -> Result<i32, Trap> {
    if b == 0 {
        return Err(Trap::DivideByZero);
    }
    Ok(a.wrapping_rem(b))
}

pub fn i32_rem_u(a: i32, b: i32) -> Result<i32, Trap> {
    if b == 0 {
        return Err(Trap::DivideByZero);
    }
    Ok(((a as u32) % (b as u32)) as i32)
}

pub fn i32_and(a: i32, b: i32) -> i32 {
    a & b
}

pub fn i32_or(a: i32, b: i32) -> i32 {
    a | b
}

pub fn i32_xor(a: i32, b: i32) -> i32 {
    a ^ b
}

pub fn i32_shl(a: i32, b: i32) -> i32 {
    a.wrapping_shl((b as u32) & 0x1f)
}

pub fn i32_shr_s(a: i32, b: i32) -> i32 {
    a.wrapping_shr((b as u32) & 0x1f)
}

pub fn i32_shr_u(a: i32, b: i32) -> i32 {
    ((a as u32).wrapping_shr((b as u32) & 0x1f)) as i32
}

pub fn i32_rotl(a: i32, b: i32) -> i32 {
    (a as u32).rotate_left((b as u32) & 0x1f) as i32
}

pub fn i32_rotr(a: i32, b: i32) -> i32 {
    (a as u32).rotate_right((b as u32) & 0x1f) as i32
}

// i64 Arithmetic
pub fn i64_clz(v: i64) -> i64 {
    v.leading_zeros() as i64
}

pub fn i64_ctz(v: i64) -> i64 {
    v.trailing_zeros() as i64
}

pub fn i64_popcnt(v: i64) -> i64 {
    v.count_ones() as i64
}

pub fn i64_add(a: i64, b: i64) -> i64 {
    a.wrapping_add(b)
}

pub fn i64_sub(a: i64, b: i64) -> i64 {
    a.wrapping_sub(b)
}

pub fn i64_mul(a: i64, b: i64) -> i64 {
    a.wrapping_mul(b)
}

pub fn i64_div_s(a: i64, b: i64) -> Result<i64, Trap> {
    if b == 0 {
        return Err(Trap::DivideByZero);
    }
    if a == i64::MIN && b == -1 {
        return Err(Trap::IntegerOverflow);
    }
    Ok(a / b)
}

pub fn i64_div_u(a: i64, b: i64) -> Result<i64, Trap> {
    if b == 0 {
        return Err(Trap::DivideByZero);
    }
    Ok(((a as u64) / (b as u64)) as i64)
}

pub fn i64_rem_s(a: i64, b: i64) -> Result<i64, Trap> {
    if b == 0 {
        return Err(Trap::DivideByZero);
    }
    Ok(a.wrapping_rem(b))
}

pub fn i64_rem_u(a: i64, b: i64) -> Result<i64, Trap> {
    if b == 0 {
        return Err(Trap::DivideByZero);
    }
    Ok(((a as u64) % (b as u64)) as i64)
}

pub fn i64_and(a: i64, b: i64) -> i64 {
    a & b
}

pub fn i64_or(a: i64, b: i64) -> i64 {
    a | b
}

pub fn i64_xor(a: i64, b: i64) -> i64 {
    a ^ b
}

pub fn i64_shl(a: i64, b: i64) -> i64 {
    a.wrapping_shl((b as u32) & 0x3f)
}

pub fn i64_shr_s(a: i64, b: i64) -> i64 {
    a.wrapping_shr((b as u32) & 0x3f)
}

pub fn i64_shr_u(a: i64, b: i64) -> i64 {
    ((a as u64).wrapping_shr((b as u32) & 0x3f)) as i64
}

pub fn i64_rotl(a: i64, b: i64) -> i64 {
    (a as u64).rotate_left((b as u32) & 0x3f) as i64
}

pub fn i64_rotr(a: i64, b: i64) -> i64 {
    (a as u64).rotate_right((b as u32) & 0x3f) as i64
}

// Conversion Instructions
pub fn i32_wrap_i64(v: i64) -> i32 {
    v as i32
}

pub fn i64_extend_i32_s(v: i32) -> i64 {
    v as i64
}

pub fn i64_extend_i32_u(v: i32) -> i64 {
    (v as u32) as i64
}

pub fn i32_extend8_s(v: i32) -> i32 {
    (v as i8) as i32
}

pub fn i32_extend16_s(v: i32) -> i32 {
    (v as i16) as i32
}

pub fn i64_extend8_s(v: i64) -> i64 {
    (v as i8) as i64
}

pub fn i64_extend16_s(v: i64) -> i64 {
    (v as i16) as i64
}

pub fn i64_extend32_s(v: i64) -> i64 {
    (v as i32) as i64
}

// WebAssembly nearest (round to nearest even)
fn f32_nearest(v: f32) -> f32 {
    // round_ties_even is the WebAssembly nearest semantics
    v.round_ties_even()
}

fn f64_nearest(v: f64) -> f64 {
    v.round_ties_even()
}

// WebAssembly min/max with NaN propagation
fn f32_min(a: f32, b: f32) -> f32 {
    if a.is_nan() || b.is_nan() {
        f32::NAN
    } else if a == 0.0 && b == 0.0 {
        // -0.0 < +0.0 for min
        if a.is_sign_negative() || b.is_sign_negative() {
            -0.0f32
        } else {
            0.0f32
        }
    } else {
        a.min(b)
    }
}

fn f32_max(a: f32, b: f32) -> f32 {
    if a.is_nan() || b.is_nan() {
        f32::NAN
    } else if a == 0.0 && b == 0.0 {
        // +0.0 > -0.0 for max
        if a.is_sign_positive() || b.is_sign_positive() {
            0.0f32
        } else {
            -0.0f32
        }
    } else {
        a.max(b)
    }
}

fn f64_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_negative() || b.is_sign_negative() {
            -0.0f64
        } else {
            0.0f64
        }
    } else {
        a.min(b)
    }
}

fn f64_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a == 0.0 && b == 0.0 {
        if a.is_sign_positive() || b.is_sign_positive() {
            0.0f64
        } else {
            -0.0f64
        }
    } else {
        a.max(b)
    }
}

// Trapping truncations
fn i32_trunc_f32_s(v: f32) -> Result<i32, Trap> {
    if v.is_nan() {
        return Err(Trap::IntegerOverflow);
    }
    let trunc = v.trunc();
    if trunc < (i32::MIN as f32) || trunc >= (i32::MAX as f32) + 1.0 {
        return Err(Trap::IntegerOverflow);
    }
    Ok(trunc as i32)
}

fn i32_trunc_f32_u(v: f32) -> Result<i32, Trap> {
    if v.is_nan() {
        return Err(Trap::IntegerOverflow);
    }
    let trunc = v.trunc();
    if trunc < 0.0 || trunc >= (u32::MAX as f32) + 1.0 {
        return Err(Trap::IntegerOverflow);
    }
    Ok((trunc as u32) as i32)
}

fn i32_trunc_f64_s(v: f64) -> Result<i32, Trap> {
    if v.is_nan() {
        return Err(Trap::IntegerOverflow);
    }
    let trunc = v.trunc();
    if trunc < (i32::MIN as f64) || trunc >= (i32::MAX as f64) + 1.0 {
        return Err(Trap::IntegerOverflow);
    }
    Ok(trunc as i32)
}

fn i32_trunc_f64_u(v: f64) -> Result<i32, Trap> {
    if v.is_nan() {
        return Err(Trap::IntegerOverflow);
    }
    let trunc = v.trunc();
    if trunc < 0.0 || trunc >= (u32::MAX as f64) + 1.0 {
        return Err(Trap::IntegerOverflow);
    }
    Ok((trunc as u32) as i32)
}

fn i64_trunc_f32_s(v: f32) -> Result<i64, Trap> {
    if v.is_nan() {
        return Err(Trap::IntegerOverflow);
    }
    let trunc = v.trunc();
    if trunc < (i64::MIN as f32) || trunc >= (i64::MAX as f32) + 1.0 {
        return Err(Trap::IntegerOverflow);
    }
    Ok(trunc as i64)
}

fn i64_trunc_f32_u(v: f32) -> Result<i64, Trap> {
    if v.is_nan() {
        return Err(Trap::IntegerOverflow);
    }
    let trunc = v.trunc();
    if trunc < 0.0 || trunc >= (u64::MAX as f32) + 1.0 {
        return Err(Trap::IntegerOverflow);
    }
    Ok((trunc as u64) as i64)
}

fn i64_trunc_f64_s(v: f64) -> Result<i64, Trap> {
    if v.is_nan() {
        return Err(Trap::IntegerOverflow);
    }
    let trunc = v.trunc();
    if trunc < (i64::MIN as f64) || trunc >= (i64::MAX as f64) + 1.0 {
        return Err(Trap::IntegerOverflow);
    }
    Ok(trunc as i64)
}

fn i64_trunc_f64_u(v: f64) -> Result<i64, Trap> {
    if v.is_nan() {
        return Err(Trap::IntegerOverflow);
    }
    let trunc = v.trunc();
    if trunc < 0.0 || trunc >= (u64::MAX as f64) + 1.0 {
        return Err(Trap::IntegerOverflow);
    }
    Ok((trunc as u64) as i64)
}

// Saturating truncations
fn i32_trunc_sat_f32_s(v: f32) -> i32 {
    if v.is_nan() {
        0
    } else if v < (i32::MIN as f32) {
        i32::MIN
    } else if v >= (i32::MAX as f32) + 1.0 {
        i32::MAX
    } else {
        v.trunc() as i32
    }
}

fn i32_trunc_sat_f32_u(v: f32) -> i32 {
    if v.is_nan() || v < 0.0 {
        0
    } else if v >= (u32::MAX as f32) + 1.0 {
        u32::MAX as i32
    } else {
        (v.trunc() as u32) as i32
    }
}

fn i32_trunc_sat_f64_s(v: f64) -> i32 {
    if v.is_nan() {
        0
    } else if v < (i32::MIN as f64) {
        i32::MIN
    } else if v >= (i32::MAX as f64) + 1.0 {
        i32::MAX
    } else {
        v.trunc() as i32
    }
}

fn i32_trunc_sat_f64_u(v: f64) -> i32 {
    if v.is_nan() || v < 0.0 {
        0
    } else if v >= (u32::MAX as f64) + 1.0 {
        u32::MAX as i32
    } else {
        (v.trunc() as u32) as i32
    }
}

fn i64_trunc_sat_f32_s(v: f32) -> i64 {
    if v.is_nan() {
        0
    } else if v < (i64::MIN as f32) {
        i64::MIN
    } else if v >= (i64::MAX as f32) + 1.0 {
        i64::MAX
    } else {
        v.trunc() as i64
    }
}

fn i64_trunc_sat_f32_u(v: f32) -> i64 {
    if v.is_nan() || v < 0.0 {
        0
    } else if v >= (u64::MAX as f32) + 1.0 {
        u64::MAX as i64
    } else {
        (v.trunc() as u64) as i64
    }
}

fn i64_trunc_sat_f64_s(v: f64) -> i64 {
    if v.is_nan() {
        0
    } else if v < (i64::MIN as f64) {
        i64::MIN
    } else if v >= (i64::MAX as f64) + 1.0 {
        i64::MAX
    } else {
        v.trunc() as i64
    }
}

fn i64_trunc_sat_f64_u(v: f64) -> i64 {
    if v.is_nan() || v < 0.0 {
        0
    } else if v >= (u64::MAX as f64) + 1.0 {
        u64::MAX as i64
    } else {
        (v.trunc() as u64) as i64
    }
}
