use ir::ValType;

use crate::value::Value;

/// Function call.
#[derive(Debug, Clone)]
pub struct Call {
    pub func_idx: u32,
    pub params: Vec<Param>,
}

/// Function call parameter.
#[derive(Debug, Clone)]
pub enum Param {
    Private(Value),
    Public(Value),
    Blind(ValType),
}

impl Param {
    pub fn ty(&self) -> ValType {
        match self {
            Param::Private(v) => v.ty(),
            Param::Public(v) => v.ty(),
            Param::Blind(ty) => *ty,
        }
    }

    /// Create a public i32 value
    pub fn public_i32(v: i32) -> Self {
        Self::Public(Value::I32(v))
    }

    /// Create a public i64 value
    pub fn public_i64(v: i64) -> Self {
        Self::Public(Value::I64(v))
    }
}
