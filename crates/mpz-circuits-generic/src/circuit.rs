//! Circuit Module
//!
//! Main circuit module.

use crate::model::Component;
use std::{
    collections::{HashMap, VecDeque},
    mem::take,
};
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
    /// Circuit gates
    gates: Vec<T>,
    /// For each input, map the gate index that provides it.
    input_map: HashMap<usize, usize>,
}

impl<T> CircuitBuilder<T>
where
    T: Component,
{
    /// Creates a new circuit builder.
    pub fn new() -> Self {
        Self {
            gates: Vec::new(),
            input_map: HashMap::new(),
        }
    }

    /// Adds a gate to the builder.
    pub fn add_gate(&mut self, gate: T) -> &mut Self {
        for &input in gate.get_inputs().iter() {
            self.input_map.insert(input, self.gates.len());
        }

        self.gates.push(gate);
        self
    }

    /// Builds the circuit.
    pub fn build(&mut self) -> Result<Circuit<T>, CircuitError> {
        self.sort_gates()?;

        Ok(Circuit::new(take(&mut self.gates)))
    }

    /// Performs a topological sort of the gates.
    ///
    /// This ensures that the gates are linearly ordered such that the
    /// dependencies (input gates) of each gate are processed before the gate itself.
    ///
    /// This requires that the gates form a directed acyclic graph (DAG).
    ///
    /// The sorting is done using Kahn's Algorithm.
    fn sort_gates(&mut self) -> Result<(), CircuitError> {
        // In-degree: the number of gates that provide input to each gate
        // This represents how many other gates need to be processed before this gate
        let mut in_degree = vec![0; self.gates.len()];
        // Adjacency list: for each gate, list the gates that directly depend on its output
        // This is used to keep track of which gates need to be updated after processing a gate
        let mut adjacency_list = vec![vec![]; self.gates.len()];

        // Populate lists
        for (i, gate) in self.gates.iter().enumerate() {
            for &output in gate.get_outputs().iter() {
                let output = self.input_map.get(&output);

                if let Some(&gate_index) = output {
                    adjacency_list[i].push(gate_index);
                    in_degree[gate_index] += 1;
                }
            }
        }

        let mut queue = VecDeque::new();
        let mut sorted_indices = Vec::with_capacity(self.gates.len());

        // Push ready-to-process nodes (no dependencies) to the queue
        for (i, &degree) in in_degree.iter().enumerate() {
            if degree == 0 {
                queue.push_back(i);
            }
        }

        // Process nodes
        while let Some(node) = queue.pop_front() {
            sorted_indices.push(node);

            // Reduce in-degree of dependent nodes
            for &neighbor in &adjacency_list[node] {
                in_degree[neighbor] -= 1;

                // If the dependent node is now ready to be processed, add it to the queue
                if in_degree[neighbor] == 0 {
                    queue.push_back(neighbor);
                }
            }
        }

        // If some node is left unprocessed, there is a cycle
        if sorted_indices.len() != self.gates.len() {
            return Err(CircuitError::CycleDetected);
        }

        // Sort the gates
        // To preserve the order of the gates we create this temporary vector of optionals
        let mut temp_gates: Vec<Option<T>> = self.gates.drain(..).map(Some).collect();
        let mut sorted_gates = Vec::with_capacity(temp_gates.len());
        for &i in &sorted_indices {
            // Whenever we take a gate from the vector we replace it with None
            // This way we avoid shifting items
            if let Some(gate) = temp_gates[i].take() {
                sorted_gates.push(gate);
            }
        }

        self.gates = sorted_gates;
        Ok(())
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
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CircuitError {
    #[error("Cycle detected")]
    CycleDetected,
}
