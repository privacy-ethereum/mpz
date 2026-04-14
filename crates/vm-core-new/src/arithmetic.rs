//! Clear arithmetic operations.

use ir::{BinaryOp, InstructionArith, Reg, UnaryOp};

use crate::{Trap, Value, VmError};

/// Execute an arithmetic instruction on clear values.
///
/// - `get`: Returns the `Value` at the given register.
///
/// Returns `(dst_reg, result_value)` on success.
pub fn execute<G>(instr: &InstructionArith, get: G) -> Result<(Reg, Value), VmError>
where
    G: Fn(Reg) -> Result<Value, VmError>,
{
    match instr {
        InstructionArith::Unary(u) => {
            let src_val = get(u.src)?;
            let result = match u.op {
                // Comparisons
                UnaryOp::I32Eqz => Value::I32(i32_eqz(src_val.as_i32()?)),
                UnaryOp::I64Eqz => Value::I32(i64_eqz(src_val.as_i64()?)),
                // i32 bit operations
                UnaryOp::I32Clz => Value::I32(i32_clz(src_val.as_i32()?)),
                UnaryOp::I32Ctz => Value::I32(i32_ctz(src_val.as_i32()?)),
                UnaryOp::I32Popcnt => Value::I32(i32_popcnt(src_val.as_i32()?)),
                // i64 bit operations
                UnaryOp::I64Clz => Value::I64(i64_clz(src_val.as_i64()?)),
                UnaryOp::I64Ctz => Value::I64(i64_ctz(src_val.as_i64()?)),
                UnaryOp::I64Popcnt => Value::I64(i64_popcnt(src_val.as_i64()?)),
                // Integer conversions
                UnaryOp::I32WrapI64 => Value::I32(i32_wrap_i64(src_val.as_i64()?)),
                UnaryOp::I64ExtendI32S => Value::I64(i64_extend_i32_s(src_val.as_i32()?)),
                UnaryOp::I64ExtendI32U => Value::I64(i64_extend_i32_u(src_val.as_i32()?)),
                UnaryOp::I32Extend8S => Value::I32(i32_extend8_s(src_val.as_i32()?)),
                UnaryOp::I32Extend16S => Value::I32(i32_extend16_s(src_val.as_i32()?)),
                UnaryOp::I64Extend8S => Value::I64(i64_extend8_s(src_val.as_i64()?)),
                UnaryOp::I64Extend16S => Value::I64(i64_extend16_s(src_val.as_i64()?)),
                UnaryOp::I64Extend32S => Value::I64(i64_extend32_s(src_val.as_i64()?)),
                // f32 unary
                UnaryOp::F32Abs => Value::F32(src_val.as_f32()?.abs()),
                UnaryOp::F32Neg => Value::F32(-src_val.as_f32()?),
                UnaryOp::F32Ceil => Value::F32(src_val.as_f32()?.ceil()),
                UnaryOp::F32Floor => Value::F32(src_val.as_f32()?.floor()),
                UnaryOp::F32Trunc => Value::F32(src_val.as_f32()?.trunc()),
                UnaryOp::F32Nearest => Value::F32(f32_nearest(src_val.as_f32()?)),
                UnaryOp::F32Sqrt => Value::F32(src_val.as_f32()?.sqrt()),
                // f64 unary
                UnaryOp::F64Abs => Value::F64(src_val.as_f64()?.abs()),
                UnaryOp::F64Neg => Value::F64(-src_val.as_f64()?),
                UnaryOp::F64Ceil => Value::F64(src_val.as_f64()?.ceil()),
                UnaryOp::F64Floor => Value::F64(src_val.as_f64()?.floor()),
                UnaryOp::F64Trunc => Value::F64(src_val.as_f64()?.trunc()),
                UnaryOp::F64Nearest => Value::F64(f64_nearest(src_val.as_f64()?)),
                UnaryOp::F64Sqrt => Value::F64(src_val.as_f64()?.sqrt()),
                // Float-to-int conversions (trapping)
                UnaryOp::I32TruncF32S => Value::I32(i32_trunc_f32_s(src_val.as_f32()?)?),
                UnaryOp::I32TruncF32U => Value::I32(i32_trunc_f32_u(src_val.as_f32()?)?),
                UnaryOp::I32TruncF64S => Value::I32(i32_trunc_f64_s(src_val.as_f64()?)?),
                UnaryOp::I32TruncF64U => Value::I32(i32_trunc_f64_u(src_val.as_f64()?)?),
                UnaryOp::I64TruncF32S => Value::I64(i64_trunc_f32_s(src_val.as_f32()?)?),
                UnaryOp::I64TruncF32U => Value::I64(i64_trunc_f32_u(src_val.as_f32()?)?),
                UnaryOp::I64TruncF64S => Value::I64(i64_trunc_f64_s(src_val.as_f64()?)?),
                UnaryOp::I64TruncF64U => Value::I64(i64_trunc_f64_u(src_val.as_f64()?)?),
                // Int-to-float conversions
                UnaryOp::F32ConvertI32S => Value::F32(src_val.as_i32()? as f32),
                UnaryOp::F32ConvertI32U => Value::F32((src_val.as_i32()? as u32) as f32),
                UnaryOp::F32ConvertI64S => Value::F32(src_val.as_i64()? as f32),
                UnaryOp::F32ConvertI64U => Value::F32((src_val.as_i64()? as u64) as f32),
                UnaryOp::F64ConvertI32S => Value::F64(src_val.as_i32()? as f64),
                UnaryOp::F64ConvertI32U => Value::F64((src_val.as_i32()? as u32) as f64),
                UnaryOp::F64ConvertI64S => Value::F64(src_val.as_i64()? as f64),
                UnaryOp::F64ConvertI64U => Value::F64((src_val.as_i64()? as u64) as f64),
                // Float-to-float conversions
                UnaryOp::F32DemoteF64 => Value::F32(src_val.as_f64()? as f32),
                UnaryOp::F64PromoteF32 => Value::F64(src_val.as_f32()? as f64),
                // Reinterpret
                UnaryOp::I32ReinterpretF32 => Value::I32(src_val.as_f32()?.to_bits() as i32),
                UnaryOp::I64ReinterpretF64 => Value::I64(src_val.as_f64()?.to_bits() as i64),
                UnaryOp::F32ReinterpretI32 => Value::F32(f32::from_bits(src_val.as_i32()? as u32)),
                UnaryOp::F64ReinterpretI64 => Value::F64(f64::from_bits(src_val.as_i64()? as u64)),
                // Saturating truncations
                UnaryOp::I32TruncSatF32S => Value::I32(i32_trunc_sat_f32_s(src_val.as_f32()?)),
                UnaryOp::I32TruncSatF32U => Value::I32(i32_trunc_sat_f32_u(src_val.as_f32()?)),
                UnaryOp::I32TruncSatF64S => Value::I32(i32_trunc_sat_f64_s(src_val.as_f64()?)),
                UnaryOp::I32TruncSatF64U => Value::I32(i32_trunc_sat_f64_u(src_val.as_f64()?)),
                UnaryOp::I64TruncSatF32S => Value::I64(i64_trunc_sat_f32_s(src_val.as_f32()?)),
                UnaryOp::I64TruncSatF32U => Value::I64(i64_trunc_sat_f32_u(src_val.as_f32()?)),
                UnaryOp::I64TruncSatF64S => Value::I64(i64_trunc_sat_f64_s(src_val.as_f64()?)),
                UnaryOp::I64TruncSatF64U => Value::I64(i64_trunc_sat_f64_u(src_val.as_f64()?)),
            };
            Ok((u.dst, result))
        }
        InstructionArith::Binary(b) => {
            let lhs_val = get(b.lhs)?;
            let rhs_val = get(b.rhs)?;
            let result = match b.op {
                // i32 comparisons
                BinaryOp::I32Eq => Value::I32(i32_eq(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32Ne => Value::I32(i32_ne(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32LtS => Value::I32(i32_lt_s(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32LtU => Value::I32(i32_lt_u(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32GtS => Value::I32(i32_gt_s(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32GtU => Value::I32(i32_gt_u(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32LeS => Value::I32(i32_le_s(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32LeU => Value::I32(i32_le_u(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32GeS => Value::I32(i32_ge_s(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32GeU => Value::I32(i32_ge_u(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                // i64 comparisons
                BinaryOp::I64Eq => Value::I32(i64_eq(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64Ne => Value::I32(i64_ne(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64LtS => Value::I32(i64_lt_s(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64LtU => Value::I32(i64_lt_u(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64GtS => Value::I32(i64_gt_s(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64GtU => Value::I32(i64_gt_u(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64LeS => Value::I32(i64_le_s(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64LeU => Value::I32(i64_le_u(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64GeS => Value::I32(i64_ge_s(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64GeU => Value::I32(i64_ge_u(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                // i32 arithmetic
                BinaryOp::I32Add => Value::I32(i32_add(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32Sub => Value::I32(i32_sub(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32Mul => Value::I32(i32_mul(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32DivS => Value::I32(i32_div_s(lhs_val.as_i32()?, rhs_val.as_i32()?)?),
                BinaryOp::I32DivU => Value::I32(i32_div_u(lhs_val.as_i32()?, rhs_val.as_i32()?)?),
                BinaryOp::I32RemS => Value::I32(i32_rem_s(lhs_val.as_i32()?, rhs_val.as_i32()?)?),
                BinaryOp::I32RemU => Value::I32(i32_rem_u(lhs_val.as_i32()?, rhs_val.as_i32()?)?),
                BinaryOp::I32And => Value::I32(i32_and(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32Or => Value::I32(i32_or(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32Xor => Value::I32(i32_xor(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32Shl => Value::I32(i32_shl(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32ShrS => Value::I32(i32_shr_s(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32ShrU => Value::I32(i32_shr_u(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32Rotl => Value::I32(i32_rotl(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                BinaryOp::I32Rotr => Value::I32(i32_rotr(lhs_val.as_i32()?, rhs_val.as_i32()?)),
                // i64 arithmetic
                BinaryOp::I64Add => Value::I64(i64_add(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64Sub => Value::I64(i64_sub(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64Mul => Value::I64(i64_mul(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64DivS => Value::I64(i64_div_s(lhs_val.as_i64()?, rhs_val.as_i64()?)?),
                BinaryOp::I64DivU => Value::I64(i64_div_u(lhs_val.as_i64()?, rhs_val.as_i64()?)?),
                BinaryOp::I64RemS => Value::I64(i64_rem_s(lhs_val.as_i64()?, rhs_val.as_i64()?)?),
                BinaryOp::I64RemU => Value::I64(i64_rem_u(lhs_val.as_i64()?, rhs_val.as_i64()?)?),
                BinaryOp::I64And => Value::I64(i64_and(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64Or => Value::I64(i64_or(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64Xor => Value::I64(i64_xor(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64Shl => Value::I64(i64_shl(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64ShrS => Value::I64(i64_shr_s(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64ShrU => Value::I64(i64_shr_u(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64Rotl => Value::I64(i64_rotl(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                BinaryOp::I64Rotr => Value::I64(i64_rotr(lhs_val.as_i64()?, rhs_val.as_i64()?)),
                // f32 comparisons
                BinaryOp::F32Eq => Value::I32((lhs_val.as_f32()? == rhs_val.as_f32()?) as i32),
                BinaryOp::F32Ne => Value::I32((lhs_val.as_f32()? != rhs_val.as_f32()?) as i32),
                BinaryOp::F32Lt => Value::I32((lhs_val.as_f32()? < rhs_val.as_f32()?) as i32),
                BinaryOp::F32Gt => Value::I32((lhs_val.as_f32()? > rhs_val.as_f32()?) as i32),
                BinaryOp::F32Le => Value::I32((lhs_val.as_f32()? <= rhs_val.as_f32()?) as i32),
                BinaryOp::F32Ge => Value::I32((lhs_val.as_f32()? >= rhs_val.as_f32()?) as i32),
                // f64 comparisons
                BinaryOp::F64Eq => Value::I32((lhs_val.as_f64()? == rhs_val.as_f64()?) as i32),
                BinaryOp::F64Ne => Value::I32((lhs_val.as_f64()? != rhs_val.as_f64()?) as i32),
                BinaryOp::F64Lt => Value::I32((lhs_val.as_f64()? < rhs_val.as_f64()?) as i32),
                BinaryOp::F64Gt => Value::I32((lhs_val.as_f64()? > rhs_val.as_f64()?) as i32),
                BinaryOp::F64Le => Value::I32((lhs_val.as_f64()? <= rhs_val.as_f64()?) as i32),
                BinaryOp::F64Ge => Value::I32((lhs_val.as_f64()? >= rhs_val.as_f64()?) as i32),
                // f32 binary arithmetic
                BinaryOp::F32Add => Value::F32(lhs_val.as_f32()? + rhs_val.as_f32()?),
                BinaryOp::F32Sub => Value::F32(lhs_val.as_f32()? - rhs_val.as_f32()?),
                BinaryOp::F32Mul => Value::F32(lhs_val.as_f32()? * rhs_val.as_f32()?),
                BinaryOp::F32Div => Value::F32(lhs_val.as_f32()? / rhs_val.as_f32()?),
                BinaryOp::F32Min => Value::F32(f32_min(lhs_val.as_f32()?, rhs_val.as_f32()?)),
                BinaryOp::F32Max => Value::F32(f32_max(lhs_val.as_f32()?, rhs_val.as_f32()?)),
                BinaryOp::F32Copysign => Value::F32(lhs_val.as_f32()?.copysign(rhs_val.as_f32()?)),
                // f64 binary arithmetic
                BinaryOp::F64Add => Value::F64(lhs_val.as_f64()? + rhs_val.as_f64()?),
                BinaryOp::F64Sub => Value::F64(lhs_val.as_f64()? - rhs_val.as_f64()?),
                BinaryOp::F64Mul => Value::F64(lhs_val.as_f64()? * rhs_val.as_f64()?),
                BinaryOp::F64Div => Value::F64(lhs_val.as_f64()? / rhs_val.as_f64()?),
                BinaryOp::F64Min => Value::F64(f64_min(lhs_val.as_f64()?, rhs_val.as_f64()?)),
                BinaryOp::F64Max => Value::F64(f64_max(lhs_val.as_f64()?, rhs_val.as_f64()?)),
                BinaryOp::F64Copysign => Value::F64(lhs_val.as_f64()?.copysign(rhs_val.as_f64()?)),
            };
            Ok((b.dst, result))
        }
    }
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
