mod call;
mod error;

pub use call::{Call, CallBuilder, CallError};
pub use error::VmError;
pub use mpz_memory_core as memory;
pub type Result<T> = core::result::Result<T, VmError>;

pub mod prelude {
    pub use crate::{CallableExt, Execute};
    pub use mpz_memory_core::{Array, MemoryExt, Slice, ViewExt};
}

use async_trait::async_trait;

use mpz_memory_core::{Memory, MemoryType, Repr, Slice, View};

/// A virtual machine.
pub trait Vm<T: MemoryType>:
    Callable<T> + Memory<T, Error = VmError> + View<T, Error = VmError>
{
}

impl<T, U> Vm<U> for T
where
    T: ?Sized + Callable<U> + Memory<U, Error = VmError> + View<U, Error = VmError>,
    U: MemoryType,
{
}

/// Interface for calling functions.
pub trait Callable<T: MemoryType> {
    /// Calls a function, returning the output.
    fn call_raw(&mut self, call: Call) -> Result<Slice>;
}

/// Extension trait for [`Callable`].
pub trait CallableExt<T: MemoryType>: Callable<T> {
    /// Calls a function, returning the output.
    fn call<R>(&mut self, call: Call) -> Result<R>
    where
        R: Repr<T>,
    {
        self.call_raw(call).map(R::from_raw)
    }
}

impl<T, M> CallableExt<M> for T
where
    T: Callable<M>,
    M: MemoryType,
{
}

#[async_trait]
pub trait Execute<Ctx> {
    /// Flushes all memory operations.
    ///
    /// This ensures all memory operations are completed.
    async fn flush(&mut self, ctx: &mut Ctx) -> Result<()>;

    /// Preprocesses the callstack.
    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<()>;

    /// Executes the callstack.
    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use mpz_memory_core::binary::Binary;

    use super::*;

    #[test]
    fn test_dyn_vm() {
        fn is_vm<T: ?Sized + Vm<Binary>>() {}

        is_vm::<dyn Vm<Binary>>();
    }
}
