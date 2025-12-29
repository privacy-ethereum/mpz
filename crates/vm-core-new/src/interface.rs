//! VM interface trait.

use mpz_common::{Context, future::MaybeDone};

use crate::{Param, Value, VmError};

/// Interface for a WebAssembly virtual machine.
pub trait Vm {
    /// Write data to memory at the specified address.
    fn write(&mut self, ptr: u32, data: &[u8]) -> Result<(), VmError>;

    /// Read data from memory at the specified address.
    fn read(&self, ptr: u32, len: usize) -> Result<Vec<u8>, VmError>;

    /// Queue a function call for execution.
    ///
    /// Returns a future that will resolve to the function's return value
    /// after `flush` is called.
    fn call(
        &mut self,
        func_idx: u32,
        args: Vec<Param>,
    ) -> Result<MaybeDone<Option<Value>>, VmError>;

    /// Execute all queued calls.
    fn flush(&mut self, ctx: &mut Context) -> impl Future<Output = Result<(), VmError>> + Send;
}
