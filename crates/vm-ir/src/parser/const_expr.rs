use wasmparser::{BinaryReader, Operator};

use crate::{ConstExpr, Error, Instruction, Reg, Result, UnsupportedFeature, ValidationError};

use super::sections::parse_heap_type;

/// Parse a constant expression (for globals, element/data offsets).
pub(super) fn parse_const_expr(reader: &mut BinaryReader) -> Result<ConstExpr> {
    let mut expr: Option<ConstExpr> = None;

    while !reader.eof() {
        let op = reader.read_operator()?;
        use Operator::*;
        let parsed = match &op {
            I32Const { value } => ConstExpr::I32(*value),
            I64Const { value } => ConstExpr::I64(*value),
            F32Const { value } => ConstExpr::F32(value.bits()),
            F64Const { value } => ConstExpr::F64(value.bits()),
            GlobalGet { global_index } => ConstExpr::GlobalGet(*global_index),
            RefNull { hty } => ConstExpr::RefNull(parse_heap_type(hty)?),
            RefFunc { function_index } => ConstExpr::RefFunc(*function_index),
            End => continue,
            _ => {
                return Err(
                    UnsupportedFeature::ConstExprInstruction(format!("{:?}", op)).into(),
                );
            }
        };
        if expr.is_some() {
            return Err(UnsupportedFeature::MultiOpConstExpr.into());
        }
        expr = Some(parsed);
    }

    expr.ok_or(Error::Validation(ValidationError::EmptyConstExpr))
}

/// Parse an element segment expression into register instructions.
pub(super) fn parse_elem_expr(reader: &mut BinaryReader) -> Result<Vec<Instruction>> {
    let mut instrs = Vec::new();
    let dummy_reg: Reg = Reg(0);

    while !reader.eof() {
        let op = reader.read_operator()?;
        use Operator::*;
        let instr = match &op {
            RefNull { hty } => Instruction::RefNull {
                dst: dummy_reg,
                ty: parse_heap_type(hty)?,
            },
            RefFunc { function_index } => Instruction::RefFunc {
                dst: dummy_reg,
                func_idx: *function_index,
            },
            End => continue,
            _ => {
                return Err(
                    UnsupportedFeature::ElemExprInstruction(format!("{:?}", op)).into(),
                );
            }
        };
        instrs.push(instr);
    }

    Ok(instrs)
}
