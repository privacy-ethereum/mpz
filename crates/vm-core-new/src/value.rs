use ir::{Instruction, ValType};

use crate::VmError;

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::I32(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::I64(v)
    }
}

impl From<f32> for Value {
    fn from(v: f32) -> Self {
        Value::F32(v)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::F64(v)
    }
}

impl Value {
    /// Get the type of this value.
    pub fn ty(&self) -> ValType {
        match self {
            Value::I32(_) => ValType::I32,
            Value::I64(_) => ValType::I64,
            Value::F32(_) => ValType::F32,
            Value::F64(_) => ValType::F64,
        }
    }

    /// Create a zero value of the given type.
    pub fn zero(ty: ValType) -> Self {
        match ty {
            ValType::I32 => Value::I32(0),
            ValType::I64 => Value::I64(0),
            ValType::F32 => Value::F32(0.0),
            ValType::F64 => Value::F64(0.0),
        }
    }

    pub(crate) fn into_const(self) -> Instruction {
        match self {
            Value::I32(v) => Instruction::I32Const(v),
            Value::I64(v) => Instruction::I64Const(v),
            Value::F32(v) => Instruction::F32Const(v.to_bits()),
            Value::F64(v) => Instruction::F64Const(v.to_bits()),
        }
    }

    pub(crate) fn as_i32(&self) -> Result<i32, VmError> {
        match self {
            Value::I32(v) => Ok(*v),
            _ => Err(VmError::TypeMismatch {
                expected: ir::ValType::I32,
                got: self.ty(),
            }),
        }
    }

    pub(crate) fn as_i64(&self) -> Result<i64, VmError> {
        match self {
            Value::I64(v) => Ok(*v),
            _ => Err(VmError::TypeMismatch {
                expected: ir::ValType::I64,
                got: self.ty(),
            }),
        }
    }

    pub(crate) fn as_f32(&self) -> Result<f32, VmError> {
        match self {
            Value::F32(v) => Ok(*v),
            _ => Err(VmError::TypeMismatch {
                expected: ir::ValType::F32,
                got: self.ty(),
            }),
        }
    }

    pub(crate) fn as_f64(&self) -> Result<f64, VmError> {
        match self {
            Value::F64(v) => Ok(*v),
            _ => Err(VmError::TypeMismatch {
                expected: ir::ValType::F64,
                got: self.ty(),
            }),
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        match self {
            Value::I32(0) => true,
            Value::I64(0) => true,
            Value::F32(v) => *v == 0.0,
            Value::F64(v) => *v == 0.0,
            _ => false,
        }
    }

    pub(crate) fn is_one(&self) -> bool {
        match self {
            Value::I32(1) => true,
            Value::I64(1) => true,
            Value::F32(v) => *v == 1.0,
            Value::F64(v) => *v == 1.0,
            _ => false,
        }
    }
}

/// Identifier for a symbolic value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolId(u32);

impl SymbolId {
    /// Returns the next id.
    pub fn next(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }

    /// Returns the id as `usize`.
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

/// State of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueState<T> {
    Clear(T),
    Symbol,
}

impl<T: Copy> ValueState<T> {
    /// Extract the clear value, returning None if encoded
    pub fn as_clear(&self) -> Result<T, VmError> {
        match self {
            ValueState::Clear(v) => Ok(*v),
            ValueState::Symbol => Err(VmError::SymbolicValue),
        }
    }

    /// Returns true if this value is a symbol.
    pub fn is_symbol(&self) -> bool {
        matches!(self, ValueState::Symbol)
    }
}

/// Internal VM value.
#[derive(Debug, Clone, Copy)]
pub enum IValue {
    I32(ValueState<i32>),
    I64(ValueState<i64>),
    F32(ValueState<f32>),
    F64(ValueState<f64>),
}

impl From<i32> for IValue {
    fn from(value: i32) -> Self {
        IValue::I32(ValueState::Clear(value))
    }
}

impl From<i64> for IValue {
    fn from(value: i64) -> Self {
        IValue::I64(ValueState::Clear(value))
    }
}

impl From<f32> for IValue {
    fn from(value: f32) -> Self {
        IValue::F32(ValueState::Clear(value))
    }
}

impl From<f64> for IValue {
    fn from(value: f64) -> Self {
        IValue::F64(ValueState::Clear(value))
    }
}

impl From<Value> for IValue {
    fn from(value: Value) -> Self {
        match value {
            Value::I32(v) => IValue::I32(ValueState::Clear(v)),
            Value::I64(v) => IValue::I64(ValueState::Clear(v)),
            Value::F32(v) => IValue::F32(ValueState::Clear(v)),
            Value::F64(v) => IValue::F64(ValueState::Clear(v)),
        }
    }
}

impl IValue {
    /// Get the type of this value.
    pub fn ty(&self) -> ValType {
        match self {
            IValue::I32(_) => ValType::I32,
            IValue::I64(_) => ValType::I64,
            IValue::F32(_) => ValType::F32,
            IValue::F64(_) => ValType::F64,
        }
    }

    /// Extract an i32 value.
    pub fn as_i32(&self) -> Result<ValueState<i32>, VmError> {
        match self {
            IValue::I32(v) => Ok(*v),
            _ => Err(VmError::TypeMismatch {
                expected: ValType::I32,
                got: self.ty(),
            }),
        }
    }

    /// Extract an i64 value.
    pub fn as_i64(&self) -> Result<ValueState<i64>, VmError> {
        match self {
            IValue::I64(v) => Ok(*v),
            _ => Err(VmError::TypeMismatch {
                expected: ValType::I64,
                got: self.ty(),
            }),
        }
    }

    /// Extract an f32 value.
    pub fn as_f32(&self) -> Result<ValueState<f32>, VmError> {
        match self {
            IValue::F32(v) => Ok(*v),
            _ => Err(VmError::TypeMismatch {
                expected: ValType::F32,
                got: self.ty(),
            }),
        }
    }

    /// Extract an f64 value.
    pub fn as_f64(&self) -> Result<ValueState<f64>, VmError> {
        match self {
            IValue::F64(v) => Ok(*v),
            _ => Err(VmError::TypeMismatch {
                expected: ValType::F64,
                got: self.ty(),
            }),
        }
    }

    /// Returns the value as a clear value.
    pub fn as_clear(&self) -> Result<Value, VmError> {
        match self {
            IValue::I32(ValueState::Clear(v)) => Ok((*v).into()),
            IValue::I64(ValueState::Clear(v)) => Ok((*v).into()),
            IValue::F32(ValueState::Clear(v)) => Ok((*v).into()),
            IValue::F64(ValueState::Clear(v)) => Ok((*v).into()),
            _ => Err(VmError::SymbolicValue),
        }
    }

    /// Returns true if this value is symbolic.
    pub fn is_symbol(&self) -> bool {
        match self {
            IValue::I32(ValueState::Symbol)
            | IValue::I64(ValueState::Symbol)
            | IValue::F32(ValueState::Symbol)
            | IValue::F64(ValueState::Symbol) => true,
            _ => false,
        }
    }

    /// Create a symbolic i32.
    pub fn i32_symbol() -> Self {
        IValue::I32(ValueState::Symbol)
    }

    /// Create a symbolic i64.
    pub fn i64_symbol() -> Self {
        IValue::I64(ValueState::Symbol)
    }

    /// Create a symbolic value of the given type.
    pub fn symbol(ty: ValType) -> Self {
        match ty {
            ValType::I32 => IValue::I32(ValueState::Symbol),
            ValType::I64 => IValue::I64(ValueState::Symbol),
            ValType::F32 => IValue::F32(ValueState::Symbol),
            ValType::F64 => IValue::F64(ValueState::Symbol),
        }
    }
}
