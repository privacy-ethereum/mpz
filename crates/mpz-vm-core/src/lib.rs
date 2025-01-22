mod call;

pub use call::{Call, CallBuilder, CallError};
pub use mpz_memory_core as memory;

pub mod prelude {
    pub use crate::{CallableExt, Execute};
    pub use mpz_memory_core::{Array, MemoryExt, Slice, ViewExt};
}

use async_trait::async_trait;

use mpz_memory_core::{Memory, MemoryType, Repr, Slice, View};

/// A virtual machine.
pub trait Vm<T: MemoryType>:
    Callable<T, Error = <Self as Vm<T>>::Error>
    + Memory<T, Error = <Self as Vm<T>>::Error>
    + View<T, Error = <Self as Vm<T>>::Error>
{
    /// Error type for the virtual machine.
    type Error: std::error::Error + Send + Sync + 'static;
}

impl<T, U, E> Vm<U> for T
where
    T: ?Sized + Callable<U, Error = E> + Memory<U, Error = E> + View<U, Error = E>,
    U: MemoryType,
    E: std::error::Error + Send + Sync + 'static,
{
    type Error = E;
}

/// Interface for calling functions.
pub trait Callable<T: MemoryType>: Memory<T, Error = <Self as Callable<T>>::Error> {
    /// Error type for calling functions.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Calls a function, returning the output.
    fn call_raw(&mut self, call: Call) -> Result<Slice, <Self as Callable<T>>::Error>;
}

/// Extension trait for [`Callable`].
pub trait CallableExt<T: MemoryType>: Callable<T> {
    /// Calls a function, returning the output.
    fn call<R>(&mut self, call: Call) -> Result<R, <Self as Callable<T>>::Error>
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
