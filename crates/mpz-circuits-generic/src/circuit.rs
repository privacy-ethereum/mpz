//! Circuit Module
//!
//! Main circuit module.

use std::marker::PhantomData;
use thiserror::Error;

#[derive(Default)]
/// Represents the circuit interface, generic over represented values.
pub struct CircuitInterface<T> {
    /// Circuit inputs.
    inputs: Vec<T>,
    /// Circuit outputs indices.
    outputs: Vec<usize>,
}

impl<T> CircuitInterface<T> {
    /// Creates a new circuit interface.
    pub fn new() -> Self {
        CircuitInterface {
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }
}

/// Generic circuit implementation.
///
/// T: Circuit interface type. This is the type the input and output values use.
/// U: Generic gate type. Must implement the Evaluate<V> trait.
/// V: Gates value type. This is the type the gates perform operations on.
pub struct Circuit<T, U, V>
where
    T: RepresentedValue<V>,
    U: Evaluate<V>,
{
    interface: CircuitInterface<T>,
    gates: Vec<U>,
    _phantom: PhantomData<V>,
}

impl<T, U, V> Circuit<T, U, V>
where
    T: RepresentedValue<V>,
    U: Evaluate<V>,
{
    /// Creates a new circuit.
    pub fn new() -> Self {
        Circuit {
            interface: CircuitInterface::<T>::new(),
            gates: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Adds a gate to the circuit.
    pub fn add_gate(&mut self, gate: U) {
        self.gates.push(gate);
    }

    /// Adds an input to the circuit.
    pub fn add_input(&mut self, input: T) {
        self.interface.inputs.push(input);
    }

    /// Adds an output to the circuit.
    pub fn add_output(&mut self, output: usize) {
        self.interface.outputs.push(output);
    }

    /// Runs the circuit and returns the output values.
    pub fn run(&mut self) -> Result<Vec<T>, CircuitError> {
        // Initialize node values.
        let mut nodes: Vec<Option<V>> = Vec::new();
        for input in &self.interface.inputs {
            nodes.push(Some(input.to_value()?));
        }

        // Evaluate gates
        for gate in &self.gates {
            gate.evaluate(&mut nodes)?;
        }

        // Collect and convert the outputs
        let mut outputs: Vec<T> = Vec::new();
        for &output_index in &self.interface.outputs {
            if let Some(node_value) = nodes.get(output_index).and_then(|v| v.as_ref()) {
                match T::from_value(node_value) {
                    Ok(repr) => outputs.push(repr),
                    Err(e) => return Err(e),
                }
            } else {
                return Err(CircuitError::MissingNodeValue(output_index));
            }
        }

        Ok(outputs)
    }
}

/// A trait that circuit gates should implement to perform an evaluation.
pub trait Evaluate<T> {
    /// Performs an evaluation. Receives a mutable slice of optional values that represent the circuit nodes.
    fn evaluate(&self, nodes: &mut Vec<Option<T>>) -> Result<(), CircuitError>;
}

/// Represented value trait.
///
/// This trait has to be implemented on the interface value type to allow its conversion to the gate value type.
pub trait RepresentedValue<T> {
    /// Converts a gate value back to the represented interface value type.
    fn from_value(value: &T) -> Result<Self, CircuitError>
    where
        Self: Sized;

    /// Converts the interface value to the gate value.
    fn to_value(&self) -> Result<T, CircuitError>;
}

/// Circuit errors.
#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("Invalid number of circuit inputs: expected {0}, got {1}")]
    InvalidInputCount(usize, usize),
    #[error("Invalid number of gate inputs: expected {0}, got {1}")]
    InvalidGateInputCount(usize, usize),
    #[error("Failed to convert external representation to internal gate value")]
    ConversionError,
    #[error("Output index out of range: {0}")]
    OutputIndexOutOfRange(usize),
    #[error("Missing node value at index {0}")]
    MissingNodeValue(usize),
    #[error("Gate evaluation failed: {0}")]
    GateEvaluationError(String),
    #[error("Generic circuit error: {0}")]
    GenericCircuitError(String),
}
