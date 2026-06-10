use mpz_vm_ir::ValType;

use crate::value::Value;

/// A request to invoke a function in a [`Module`](mpz_vm_ir::Module).
///
/// A call identifies the target function by its index within the module and
/// supplies one [`Param`] for each of the function's parameters.
#[derive(Debug, Clone)]
pub struct Call {
    /// The index of the function to invoke within the module.
    pub func_idx: u32,
    /// The arguments passed to the function, one per parameter.
    pub params: Vec<Param>,
}

/// An argument supplied to a function call.
///
/// Each variant determines both the value and its
/// [`Visibility`](crate::Visibility): whether it is known to the caller, shared
/// publicly, or hidden from the caller entirely.
#[derive(Debug, Clone)]
pub enum Param {
    /// A private argument whose value is known to the caller but kept secret.
    Private(Value),
    /// A public argument whose value is known to all parties.
    Public(Value),
    /// A blinded argument of the given type whose value is unknown to the
    /// caller.
    Blind(ValType),
}

impl Param {
    /// Returns the type of this argument.
    pub fn ty(&self) -> ValType {
        match self {
            Param::Private(v) => v.ty(),
            Param::Public(v) => v.ty(),
            Param::Blind(ty) => *ty,
        }
    }

    /// Creates a public [`I32`](ValType::I32) argument with the given value.
    pub fn public_i32(v: i32) -> Self {
        Self::Public(Value::I32(v))
    }
}
