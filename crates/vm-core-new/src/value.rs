use ir::ValType;

/// Errors related to value type conversions.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    #[error("type mismatch: expected {expected:?}, got {got:?}")]
    TypeMismatch { expected: ValType, got: ValType },
}

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
    pub fn ty(&self) -> ValType {
        match self {
            Value::I32(_) => ValType::I32,
            Value::I64(_) => ValType::I64,
            Value::F32(_) => ValType::F32,
            Value::F64(_) => ValType::F64,
        }
    }

    pub fn zero(ty: ValType) -> Self {
        match ty {
            ValType::I32 => Value::I32(0),
            ValType::I64 => Value::I64(0),
            ValType::F32 => Value::F32(0.0),
            ValType::F64 => Value::F64(0.0),
        }
    }

    pub fn to_le_bytes(&self) -> [u8; 8] {
        match self {
            Value::I32(v) => (*v as i64).to_le_bytes(),
            Value::I64(v) => v.to_le_bytes(),
            Value::F32(v) => (v.to_bits() as u64).to_le_bytes(),
            Value::F64(v) => v.to_bits().to_le_bytes(),
        }
    }

    pub fn as_i32(&self) -> Result<i32, ValueError> {
        match self {
            Value::I32(v) => Ok(*v),
            _ => Err(ValueError::TypeMismatch {
                expected: ValType::I32,
                got: self.ty(),
            }),
        }
    }

    pub fn as_i64(&self) -> Result<i64, ValueError> {
        match self {
            Value::I64(v) => Ok(*v),
            _ => Err(ValueError::TypeMismatch {
                expected: ValType::I64,
                got: self.ty(),
            }),
        }
    }

    pub fn as_f32(&self) -> Result<f32, ValueError> {
        match self {
            Value::F32(v) => Ok(*v),
            _ => Err(ValueError::TypeMismatch {
                expected: ValType::F32,
                got: self.ty(),
            }),
        }
    }

    pub fn as_f64(&self) -> Result<f64, ValueError> {
        match self {
            Value::F64(v) => Ok(*v),
            _ => Err(ValueError::TypeMismatch {
                expected: ValType::F64,
                got: self.ty(),
            }),
        }
    }

}
