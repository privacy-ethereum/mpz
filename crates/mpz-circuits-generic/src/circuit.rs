//! Circuit Module
//!
//! Main circuit module.

use crate::model::{Component, Executable, Executor};
use thiserror::Error;

/// A `CircuitBuilder` struct that represents a builder for a circuit.
///
/// This struct is responsible for assembling a collection of gates into a circuit.
///
/// The built output is ensured to be a directed acyclic graph (DAG), and the gates
/// topologically sorted in the order they should be executed.
pub struct CircuitBuilder<T>
where
    T: Component,
{
    gates: Vec<T>,
}

impl<T> CircuitBuilder<T>
where
    T: Component,
{
    /// Creates a new circuit builder.
    pub fn new() -> Self {
        Self { gates: Vec::new() }
    }

    /// Adds a gate to the builder.
    pub fn add_gate(&mut self, gate: T) -> &mut Self {
        self.gates.push(gate);
        self
    }

    /// Builds a circuit.
    /// This method verifies that the circuit is directed and acyclic.
    /// Sorts the gates topologically.
    pub fn build(self) -> Result<Circuit<T>, CircuitError> {
        Ok(Circuit::new(self.gates))
    }
}

/// Represents a circuit modeled as a directed acyclic graph (DAG).
///
/// - Each node in the circuit is an indexed point within an external array.
/// - Each gate acts as a unit of logic that connects these nodes.
///
/// Use the `CircuitBuilder` struct to ensure the circuit is directed and acyclic.
#[derive(Debug)]
pub struct Circuit<T> {
    gates: Vec<T>,
}

impl<T> Circuit<T> {
    /// Creates a new circuit.
    fn new(gates: Vec<T>) -> Self {
        Self { gates }
    }

    /// Returns the gates.
    pub fn gates(&self) -> &[T] {
        &self.gates
    }
}

impl<T, U> Executable<T> for Circuit<U>
where
    U: Executable<T>,
{
    type Error = CircuitError;
}

pub struct SequentialExecutor;

impl<T, U> Executor<T, Circuit<U>> for SequentialExecutor
where
    U: Component + Executable<T> + Executor<T, U>,
    Circuit<U>: Executable<T, Error = CircuitError>,
{
    fn custom_execution(
        &self,
        executable: &Circuit<U>,
        memory: &mut [T],
    ) -> Result<(), <Circuit<U> as Executable<T>>::Error> {
        for gate in executable.gates() {
            gate.custom_execution(gate, memory)
                .map_err(|_| CircuitError::CircuitExecutionError)?;
        }

        Ok(())
    }
}

/// Circuit errors.
#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("Cycle detected involving gate {0}")]
    CycleDetected(usize),
    #[error("Gate execution failed: {0}")]
    GateExecutionError(String),
    #[error("Generic circuit error: {0}")]
    GenericCircuitError(String),
    #[error("Missing node value at index {0}")]
    MissingNodeValue(usize),
    #[error("Output index out of range: {0}")]
    OutputIndexOutOfRange(usize),
    #[error("Topological sort failed")]
    TopologicalSortFailed,
    #[error("Circuit execution error")]
    CircuitExecutionError,
}
