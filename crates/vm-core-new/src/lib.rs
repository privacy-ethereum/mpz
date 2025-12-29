//! A minimal WebAssembly interpreter for integer-only WASM modules.
//!
//! This crate provides a simple stack-based virtual machine that can execute
//! WebAssembly modules parsed by the `ir` crate. Only integer operations are
//! supported (i32, i64).

pub mod arithmetic;
mod backend;
mod call;
mod error;
pub mod ideal;
mod interface;
mod memory;
pub mod ops;
mod stack;
mod state;
pub(crate) mod trace;
pub mod value;

pub use backend::Backend;
pub use call::{Call, RunResult};
pub use error::{Trap, VmError};
pub use interface::Vm;
use ir::Function;
pub use ir::{Module, ValType};
pub use memory::Memory;
pub use ops::{HostFnId, SymbolicOp, SymbolicOps};
pub use stack::OperandStack;
pub use state::State;
pub use trace::Trace;

use value::Value;

use std::collections::{BTreeMap, VecDeque};

use mpz_common::{
    Context,
    future::{MaybeDone, Sender, new_output},
};

use crate::value::IValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Public,
    Blind,
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

/// Blocked execution context waiting for decode resolution.
#[derive(Debug)]
struct BlockedContext {
    call_id: usize,
    call: Call,
    output: Sender<Result<Option<Value>, VmError>>,
}

/// Queued call waiting for blocked context to complete.
#[derive(Debug)]
struct QueuedCall {
    call: Call,
    output: Sender<Result<Option<Value>, VmError>>,
}

#[derive(Debug, Default)]
pub(crate) struct HostState {
    decode_id: usize,
    decoded: BTreeMap<usize, Value>,
}

impl HostState {
    pub(crate) fn register_decode(&mut self, value: IValue) -> usize {
        let id = self.decode_id;
        self.decode_id += 1;
        if let Ok(value) = value.as_clear() {
            self.decoded.insert(id, value);
        }
        id
    }

    pub(crate) fn resolve_decode(&mut self, id: usize) -> Option<Value> {
        self.decoded.remove(&id)
    }

    pub(crate) fn set_decode(&mut self, id: usize, value: Value) {
        self.decoded.insert(id, value);
    }

    /// Returns the current decode ID counter.
    pub(crate) fn decode_id(&self) -> usize {
        self.decode_id
    }

    /// Returns the next decode ID and increments the counter.
    pub(crate) fn next_decode_id(&mut self) -> usize {
        let id = self.decode_id;
        self.decode_id += 1;
        id
    }
}

/// VM instance.
#[derive(Debug)]
pub struct Instance<B> {
    module: Module,
    /// Symbolic executor backend.
    backend: B,
    state: State,
    host_state: HostState,
    /// Blocked context waiting for decode resolution.
    blocked_context: Option<BlockedContext>,
    /// Queued calls to execute after unblock.
    queued_calls: VecDeque<QueuedCall>,
    /// Next call ID for tracking inputs per call.
    next_call_id: usize,
}

impl<B: Backend> Instance<B> {
    /// Creates a new VM instance.
    pub fn new(module: Module, backend: B) -> Result<Self, VmError> {
        let state = State::new(&module)?;
        Ok(Self {
            module,
            backend,
            state,
            host_state: HostState::default(),
            blocked_context: None,
            queued_calls: VecDeque::new(),
            next_call_id: 0,
        })
    }

    /// Returns a reference to the module.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Allocates in linear memory, returning a pointer to the allocation.
    ///
    /// # Arguments
    ///
    /// * `old_ptr` - pointer to existing allocation (or 0 for new allocation)
    /// * `old_size` - size of existing allocation (or 0 for new allocation)
    /// * `align` - required alignment
    /// * `new_size` - requested new size (or 0 to free)
    pub fn realloc(
        &mut self,
        _old_ptr: u32,
        _old_len: u32,
        _align: u32,
        _new_len: u32,
    ) -> Result<u32, VmError> {
        todo!()
    }

    /// Writes public data to the provided pointer.
    pub fn write_public(&mut self, _ptr: u32, _data: &[u8]) -> Result<(), VmError> {
        todo!()
    }

    /// Writes private data to the provided pointer.
    pub fn write_private(&mut self, _ptr: u32, _data: &[u8]) -> Result<(), VmError> {
        todo!()
    }

    /// Writes blind data to the provided pointer.
    pub fn write_blind(&mut self, _ptr: u32, _len: usize) -> Result<(), VmError> {
        todo!()
    }

    /// Execute a function call and build its trace.
    ///
    /// The function is executed immediately and its trace is stored internally.
    /// Returns a future that will resolve to the function's return value.
    /// - Clear returns resolve immediately
    /// - Symbolic returns are deferred until trace resolution
    /// - If execution blocks on a `wait` call, the context is stored and
    ///   subsequent calls are queued
    ///
    /// The outer Result is for validation errors (bad function index, type
    /// mismatch). The inner Result (in MaybeDone) is for runtime errors
    /// (traps) during execution.
    pub fn call(
        &mut self,
        func_idx: u32,
        args: Vec<Param>,
    ) -> Result<MaybeDone<Result<Option<Value>, VmError>>, VmError> {
        self.call_inner(func_idx, args, false)
    }

    /// Calls a function with automatic decoding of symbolic return values.
    ///
    /// This is like `call()` but sets the `decode_return` flag on the Call,
    /// which causes symbolic return values to be automatically decoded.
    /// Use this when calling functions that may return symbolic values
    /// (e.g., functions called with private inputs that don't explicitly
    /// decode their return values).
    pub fn call_with_decode(
        &mut self,
        func_idx: u32,
        args: Vec<Param>,
    ) -> Result<MaybeDone<Result<Option<Value>, VmError>>, VmError> {
        self.call_inner(func_idx, args, true)
    }

    /// Internal call implementation.
    fn call_inner(
        &mut self,
        func_idx: u32,
        args: Vec<Param>,
        decode_return: bool,
    ) -> Result<MaybeDone<Result<Option<Value>, VmError>>, VmError> {
        let func = self
            .module
            .function(func_idx)
            .ok_or(VmError::UndefinedFunction(func_idx))?;

        let func = match func {
            Function::Import(_) => {
                return Err(VmError::InvalidFunction(func_idx));
            }
            Function::Local(func) => func,
        };

        // Validate single-value return (multi-value not supported)
        if func.func_type().results.len() > 1 {
            return Err(VmError::Unsupported("multi-value return".into()));
        }

        // Validate argument count
        if args.len() != func.func_type().params.len() {
            return Err(VmError::TypeMismatch {
                expected: ir::ValType::I32, // placeholder
                got: ir::ValType::I64,      // placeholder
            });
        }

        // Validate argument types.
        for (arg, expected_ty) in args.iter().zip(&func.func_type().params) {
            if &arg.ty() != expected_ty {
                return Err(VmError::TypeMismatch {
                    expected: *expected_ty,
                    got: arg.ty(),
                });
            }
        }

        // Allocate call ID for this call
        let call_id = self.next_call_id;
        self.next_call_id += 1;

        let mut iargs = Vec::new();
        for arg in args {
            let arg = match arg {
                Param::Private(value) => {
                    let ivalue = IValue::symbol(value.ty());
                    self.backend.push_private(call_id, value)?;
                    ivalue
                }
                Param::Public(value) => IValue::from(value),
                Param::Blind(ty) => {
                    self.backend.push_blind(call_id, ty)?;
                    IValue::symbol(ty)
                }
            };
            iargs.push(arg);
        }

        let mut call = Call::new(func_idx, &func, iargs);
        if decode_return {
            call.set_decode_return();
        }
        let (sender, output) = new_output();

        // If there's a blocked context, queue this validated call
        if self.blocked_context.is_some() {
            self.queued_calls.push_back(QueuedCall {
                call,
                output: sender,
            });
            return Ok(output);
        }

        // Execute
        match call.run(&self.module, &mut self.state, &mut self.host_state) {
            Ok(RunResult::Complete { result, ops }) => {
                if let Some(ops) = ops {
                    self.backend.push_ops(call_id, ops);
                }
                sender.send(Ok(result));
            }
            Ok(RunResult::Blocked { ops }) => {
                if let Some(ops) = ops {
                    self.backend.push_ops(call_id, ops);
                }
                self.blocked_context = Some(BlockedContext {
                    call_id,
                    call,
                    output: sender,
                });
            }
            Err(e) => {
                sender.send(Err(e));
            }
        }

        Ok(output)
    }

    /// Runs the instance to completion.
    ///
    /// This executes all pending ops in the backend (exchanging values
    /// with peer), and resumes any blocked contexts. Loops until all ops
    /// are processed and all blocked contexts are resolved.
    pub async fn run(&mut self, ctx: &mut Context) -> Result<(), VmError> {
        loop {
            // Execute backend (exchanges values, processes ops)
            self.backend
                .execute(ctx, &self.module, &mut self.host_state)
                .await?;

            if let Some(mut blocked) = self.blocked_context.take() {
                let call_id = blocked.call_id;
                match blocked
                    .call
                    .run(&self.module, &mut self.state, &mut self.host_state)?
                {
                    RunResult::Complete { result, ops } => {
                        if let Some(ops) = ops {
                            self.backend.push_ops(call_id, ops);
                        }
                        blocked.output.send(Ok(result));
                    }
                    RunResult::Blocked { ops } => {
                        if let Some(ops) = ops {
                            self.backend.push_ops(call_id, ops);
                        }
                        self.blocked_context = Some(blocked);
                        continue;
                    }
                }
            }

            if let Some(_next) = self.queued_calls.pop_front() {
                todo!()
            }

            break;
        }

        Ok(())
    }
}
