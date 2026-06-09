//! Runtime values and their associated errors.
//!
//! A [`Value`] is a concrete, typed scalar matching one of the WebAssembly
//! numeric [`ValType`]s. Operations that interpret a value as a specific type
//! fail with a [`ValueError`] when the value's actual type does not match.

use mpz_vm_ir::ValType;

/// An error produced when a [`Value`] does not have the expected type.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    /// The value's type did not match the type required by the operation.
    #[error("type mismatch: expected {expected:?}, got {got:?}")]
    TypeMismatch {
        /// The [`ValType`] the operation required.
        expected: ValType,
        /// The actual [`ValType`] of the value.
        got: ValType,
    },
}

/// A concrete, typed scalar value.
///
/// Each variant corresponds to one of the WebAssembly numeric [`ValType`]s.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Value {
    /// A 32-bit integer.
    I32(i32),
    /// A 64-bit integer.
    I64(i64),
    /// A 32-bit floating-point number.
    F32(f32),
    /// A 64-bit floating-point number.
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
    /// Returns the [`ValType`] of this value.
    pub fn ty(&self) -> ValType {
        match self {
            Value::I32(_) => ValType::I32,
            Value::I64(_) => ValType::I64,
            Value::F32(_) => ValType::F32,
            Value::F64(_) => ValType::F64,
        }
    }

    pub(crate) fn zero(ty: ValType) -> Self {
        match ty {
            ValType::I32 => Value::I32(0),
            ValType::I64 => Value::I64(0),
            ValType::F32 => Value::F32(0.0),
            ValType::F64 => Value::F64(0.0),
        }
    }

    /// Returns the 8-byte little-endian representation of this value.
    ///
    /// Integer values are sign- or zero-extended to 64 bits, and
    /// floating-point values are encoded from their IEEE 754 bit patterns
    /// widened to 64 bits, so every variant yields exactly 8 bytes.
    pub fn to_le_bytes(&self) -> [u8; 8] {
        match self {
            Value::I32(v) => (*v as i64).to_le_bytes(),
            Value::I64(v) => v.to_le_bytes(),
            Value::F32(v) => (v.to_bits() as u64).to_le_bytes(),
            Value::F64(v) => v.to_bits().to_le_bytes(),
        }
    }

    /// Returns the contained `i32`.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::TypeMismatch`] if this value is not an
    /// [`I32`](Self::I32).
    pub fn as_i32(&self) -> Result<i32, ValueError> {
        match self {
            Value::I32(v) => Ok(*v),
            _ => Err(ValueError::TypeMismatch {
                expected: ValType::I32,
                got: self.ty(),
            }),
        }
    }

    pub(crate) fn as_i64(&self) -> Result<i64, ValueError> {
        match self {
            Value::I64(v) => Ok(*v),
            _ => Err(ValueError::TypeMismatch {
                expected: ValType::I64,
                got: self.ty(),
            }),
        }
    }

    pub(crate) fn as_f32(&self) -> Result<f32, ValueError> {
        match self {
            Value::F32(v) => Ok(*v),
            _ => Err(ValueError::TypeMismatch {
                expected: ValType::F32,
                got: self.ty(),
            }),
        }
    }

    pub(crate) fn as_f64(&self) -> Result<f64, ValueError> {
        match self {
            Value::F64(v) => Ok(*v),
            _ => Err(ValueError::TypeMismatch {
                expected: ValType::F64,
                got: self.ty(),
            }),
        }
    }
}
