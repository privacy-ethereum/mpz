mod call;

pub use call::{Call, CallBuilder, CallError};
pub use mpz_memory_core as memory;

pub mod prelude {
    pub use crate::{Execute, VmExt};
    pub use mpz_memory_core::{Array, MemoryExt, Slice, ViewExt};
}

use async_trait::async_trait;

use mpz_memory_core::{Memory, MemoryType, Repr, Slice};

/// Virtual machine.
pub trait Vm<T: MemoryType>: Memory<T, Error = <Self as Vm<T>>::Error> {
    /// Error type for calling functions.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Calls a function, returning the output.
    fn call_raw(&mut self, call: Call) -> Result<Slice, <Self as Vm<T>>::Error>;
}

/// Extension trait for [`Callable`].
pub trait VmExt<T: MemoryType>: Vm<T> {
    /// Calls a function, returning the output.
    fn call<R>(&mut self, call: Call) -> Result<R, <Self as Vm<T>>::Error>
    where
        R: Repr<T>,
    {
        self.call_raw(call).map(R::from_raw)
    }
}

impl<T, M> VmExt<M> for T
where
    T: Vm<M>,
    M: MemoryType,
{
}

#[async_trait]
pub trait Execute<Ctx> {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Flushes all memory operations.
    ///
    /// This ensures all memory operations are completed.
    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error>;

    /// Preprocesses the callstack.
    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error>;

    /// Executes the callstack.
    async fn execute(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error>;
}
