use ir::{Module, ValType};
use mpz_common::Context;

use crate::{HostState, VmError, ops::SymbolicOps, value::Value};

/// Backend for executing symbolic operations.
pub trait Backend {
    /// Push a private value input for the given call.
    fn push_private(&mut self, call_id: usize, value: Value) -> Result<(), VmError>;

    /// Push a blind value input for the given call.
    fn push_blind(&mut self, call_id: usize, ty: ValType) -> Result<(), VmError>;

    /// Push symbolic operations to the backend for the given call.
    fn push_ops(&mut self, call_id: usize, ops: SymbolicOps);

    /// Returns true if there are pending operations to execute.
    fn has_pending_ops(&self) -> bool;

    fn execute(
        &mut self,
        ctx: &mut Context,
        module: &Module,
        host_state: &mut HostState,
    ) -> impl std::future::Future<Output = Result<(), VmError>> + Send;
}
