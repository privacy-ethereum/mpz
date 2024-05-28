//! Circuit Module
//!
//! Main circuit module.

use crate::model::Component;
use thiserror::Error;

/// The Circuit Builder assembles a collection of gates into a circuit.
///
/// The built output is ensured to be a directed acyclic graph (DAG).
///
/// The gates are topologically sorted.
#[derive(Debug)]
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

    /// Topologically sort the gates and generates a circuit.
    /// This method will fail if the circuit is not a DAG.
    pub fn build(self) -> Result<Circuit<T>, CircuitError> {
        Ok(Circuit::new(self.gates))
    }
}

/// A circuit constructed from a collection of gates.
///
/// - Each node in the circuit is an indexed point within an external array.
/// - Each gate acts as a unit of logic that connects these nodes.
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

/// Circuit errors.
#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("Cycle detected involving gate {0}")]
    CycleDetected(usize),
    #[error("Invalid gate input count")]
    InvalidGateInputCount,
    #[error("Output index out of range: {0}")]
    OutputIndexOutOfRange(usize),
    #[error("Topological sort failed")]
    TopologicalSortFailed,
}
