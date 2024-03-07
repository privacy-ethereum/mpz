//! This crate provides an implementation of garbled circuit protocols to facilitate MPC.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;

use config::Visibility;
use mpz_circuits::{
    types::{PrimitiveType, StaticValueType, Value, ValueType},
    Circuit,
};

pub mod config;
pub(crate) mod evaluator;
pub(crate) mod generator;
pub(crate) mod internal_circuits;
pub(crate) mod memory;
pub mod ot;
pub mod protocol;
mod threadpool;
pub mod value;

pub use evaluator::{Evaluator, EvaluatorConfig, EvaluatorConfigBuilder, EvaluatorError};
pub use generator::{Generator, GeneratorConfig, GeneratorConfigBuilder, GeneratorError};
pub use memory::{AssignedValues, ValueMemory};
pub use threadpool::ThreadPool;

use utils::id::NestedId;
use value::{ArrayRef, ValueId, ValueRef};

/// Errors that can occur when using an implementation of [`Vm`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VmError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error(transparent)]
    ExecutionError(#[from] ExecutionError),
    #[error(transparent)]
    ProveError(#[from] ProveError),
    #[error(transparent)]
    VerifyError(#[from] VerifyError),
    #[error(transparent)]
    DecodeError(#[from] DecodeError),
    #[error("thread pools must have at least one thread")]
    ThreadPoolEmpty,
    #[error("thread already exists: {0}")]
    ThreadAlreadyExists(String),
    #[error("vm is shutdown")]
    Shutdown,
}

/// Errors that can occur when interacting with memory.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum MemoryError {
    #[error("duplicate value id: {0:?}")]
    DuplicateValueId(ValueId),
    #[error("duplicate value: {0:?}")]
    DuplicateValue(ValueRef),
    #[error("value with id {0} has not been defined")]
    Undefined(String),
    #[error("attempted to create an invalid array: {0}")]
    InvalidArray(String),
    #[error(transparent)]
    Assignment(#[from] AssignmentError),
}

/// Errors that can occur when assigning values.
#[derive(Debug, thiserror::Error)]
pub enum AssignmentError {
    /// The value is already assigned.
    #[error("value already assigned: {0:?}")]
    Duplicate(ValueId),
    /// Can not assign to a blind input value.
    #[error("can not assign to a blind input value: {0:?}")]
    BlindInput(ValueId),
    /// Can not assign to an output value.
    #[error("can not assign to an output value: {0:?}")]
    Output(ValueId),
    /// Attempted to assign a value with an invalid type.
    #[error("invalid value type {actual:?} for {value:?}, expected {expected:?}")]
    Type {
        /// The value reference.
        value: ValueRef,
        /// The expected type.
        expected: ValueType,
        /// The actual type.
        actual: ValueType,
    },
}

/// Errors that can occur when loading a circuit.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// IO error.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    /// Protocol error.
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur when executing a circuit.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ExecutionError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur when proving the output of a circuit.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ProveError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur when verifying the output of a circuit.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum VerifyError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("invalid proof")]
    InvalidProof,
}

/// Errors that can occur when decoding values.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum DecodeError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ProtocolError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// This trait provides an abstraction of MPC, modeling it as a multi-threaded virtual machine.
#[async_trait]
pub trait Vm {
    /// The type of thread.
    type Thread: Thread + Send + 'static;

    /// Creates a new thread.
    async fn new_thread(&mut self, id: &str) -> Result<Self::Thread, VmError>;

    /// Creates a new thread pool.
    ///
    /// A thread pool must have at least one thread.
    async fn new_thread_pool(
        &mut self,
        id: &str,
        thread_count: usize,
    ) -> Result<ThreadPool<Self::Thread>, VmError> {
        if thread_count == 0 {
            return Err(VmError::ThreadPoolEmpty);
        }

        let mut id = NestedId::new(id).append_counter();
        let mut threads = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            threads.push(
                self.new_thread(&id.increment_in_place().to_string())
                    .await?,
            );
        }
        Ok(ThreadPool::new(threads))
    }
}

/// This trait provides an abstraction of a thread in an MPC virtual machine.
pub trait Thread: Memory {}

/// This trait provides methods for interacting with values in memory.
pub trait Memory {
    /// Adds a new input value, returning a reference to it.
    fn new_input_with_type(
        &self,
        id: &str,
        typ: ValueType,
        visibility: Visibility,
    ) -> Result<ValueRef, MemoryError>;

    /// Adds a new input value, returning a reference to it.
    fn new_input<T: StaticValueType>(
        &self,
        id: &str,
        visibility: Visibility,
    ) -> Result<ValueRef, MemoryError> {
        self.new_input_with_type(id, T::value_type(), visibility)
    }

    /// Adds a new public input value, returning a reference to it.
    fn new_public_input<T: StaticValueType>(&self, id: &str) -> Result<ValueRef, MemoryError> {
        self.new_input::<T>(id, Visibility::Public)
    }

    /// Adds a new public array input value, returning a reference to it.
    fn new_public_array_input<T: PrimitiveType>(
        &self,
        id: &str,
        len: usize,
    ) -> Result<ValueRef, MemoryError> {
        self.new_input_with_type(id, ValueType::new_array::<T>(len), Visibility::Public)
    }

    /// Adds a new private input value, returning a reference to it.
    fn new_private_input<T: StaticValueType>(&self, id: &str) -> Result<ValueRef, MemoryError> {
        self.new_input::<T>(id, Visibility::Private)
    }

    /// Adds a new private array input value, returning a reference to it.
    fn new_private_array_input<T: PrimitiveType>(
        &self,
        id: &str,
        len: usize,
    ) -> Result<ValueRef, MemoryError> {
        self.new_input_with_type(id, ValueType::new_array::<T>(len), Visibility::Private)
    }

    /// Adds a new blind input value, returning a reference to it.
    fn new_blind_input<T: StaticValueType>(&self, id: &str) -> Result<ValueRef, MemoryError> {
        self.new_input::<T>(id, Visibility::Blind)
    }

    /// Adds a new blind array input value, returning a reference to it.
    fn new_blind_array_input<T: PrimitiveType>(
        &self,
        id: &str,
        len: usize,
    ) -> Result<ValueRef, MemoryError> {
        self.new_input_with_type(id, ValueType::new_array::<T>(len), Visibility::Blind)
    }

    /// Adds a new output value, returning a reference to it.
    fn new_output_with_type(&self, id: &str, typ: ValueType) -> Result<ValueRef, MemoryError>;

    /// Adds a new output value, returning a reference to it.
    fn new_output<T: StaticValueType>(&self, id: &str) -> Result<ValueRef, MemoryError> {
        self.new_output_with_type(id, T::value_type())
    }

    /// Creates a new array output value, returning a reference to it.
    fn new_array_output<T: PrimitiveType>(
        &self,
        id: &str,
        len: usize,
    ) -> Result<ValueRef, MemoryError> {
        self.new_output_with_type(id, ValueType::new_array::<T>(len))
    }

    /// Assigns a value.
    fn assign(&self, value_ref: &ValueRef, value: impl Into<Value>) -> Result<(), MemoryError>;

    /// Assigns a value.
    fn assign_by_id(&self, id: &str, value: impl Into<Value>) -> Result<(), MemoryError>;

    /// Returns a value if it exists.
    fn get_value(&self, id: &str) -> Option<ValueRef>;

    /// Returns the type of a value.
    fn get_value_type(&self, value_ref: &ValueRef) -> ValueType;

    /// Returns the type of a value if it exists.
    fn get_value_type_by_id(&self, id: &str) -> Option<ValueType>;

    /// Creates an array from the provided values.
    ///
    /// All values must be of the same primitive type.
    fn array_from_values(&self, values: &[ValueRef]) -> Result<ValueRef, MemoryError> {
        if values.is_empty() {
            return Err(MemoryError::InvalidArray(
                "cannot create an array with no values".to_string(),
            ));
        }

        let mut ids = Vec::with_capacity(values.len());
        let elem_typ = self.get_value_type(&values[0]);
        for value in values {
            let ValueRef::Value { id } = value else {
                return Err(MemoryError::InvalidArray(
                    "an array can only contain primitive types".to_string(),
                ));
            };

            let value_typ = self.get_value_type(value);

            if value_typ != elem_typ {
                return Err(MemoryError::InvalidArray(format!(
                    "all values in an array must have the same type, expected {:?}, got {:?}",
                    elem_typ, value_typ
                )));
            };

            ids.push(id.clone());
        }

        Ok(ValueRef::Array(ArrayRef::new(ids)))
    }
}

/// This trait provides methods for loading a circuit.
///
/// Implementations may perform pre-processing prior to execution.
#[async_trait]
pub trait Load {
    /// Loads a circuit with the provided input and output values.
    async fn load(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), LoadError>;
}

/// This trait provides methods for executing a circuit.
#[async_trait]
pub trait Execute {
    /// Executes a circuit with the provided inputs, assigning to the provided output values
    async fn execute(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), ExecutionError>;
}

/// This trait provides methods for proving the authenticity and correctness of the output of a
/// circuit.
#[async_trait]
pub trait Prove {
    /// Executes the provided circuit as the prover, assigning to the provided output values.
    async fn execute_prove(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), ProveError>;

    /// Proves the the authenticity and correctness of the provided values.
    async fn prove(&mut self, values: &[ValueRef]) -> Result<(), ProveError>;
}

/// This trait provides methods for verifying the authenticity and correctness of the output of a
/// circuit.
#[async_trait]
pub trait Verify {
    /// Executes the provided circuit as the verifier, assigning to the provided output values.
    async fn execute_verify(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), VerifyError>;

    /// Verifies the authenticity and correctness of the provided values against the expected values.
    async fn verify(
        &mut self,
        values: &[ValueRef],
        expected_values: &[Value],
    ) -> Result<(), VerifyError>;
}

/// This trait provides methods for decoding values.
#[async_trait]
pub trait Decode {
    /// Decodes the provided values, returning the plaintext values to all parties.
    async fn decode(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError>;
}

/// This trait provides methods for decoding values with different privacy configurations.
#[async_trait]
pub trait DecodePrivate {
    /// Decodes the provided values, returning the plaintext values to only this party.
    async fn decode_private(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError>;

    /// Decodes the provided values, returning the plaintext values to the other party(s).
    async fn decode_blind(&mut self, values: &[ValueRef]) -> Result<(), DecodeError>;

    /// Decodes the provided values, returning additive shares of plaintext values to all parties.
    async fn decode_shared(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError>;
}
