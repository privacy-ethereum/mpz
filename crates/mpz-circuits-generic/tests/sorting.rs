//! Sorting tests.
//!
//! This module aims to test the topological sorting of the gates in the circuit.

use mpz_circuit_generic::model::Component;

/// Binary gate value.
#[derive(Debug, Clone)]
pub enum BinaryValue {
    /// Binary zero.
    Zero,
    /// Binary one.
    One,
}

#[derive(Debug, Clone, PartialEq)]
/// Binary gates.
pub enum BinaryOperation {
    /// AND Operation.
    AND,
    /// NOT Operation.
    NOT,
    /// XOR Operation.
    XOR,
}

/// Binary gate.
#[derive(Debug, Clone)]
pub struct BinaryGate {
    /// Gate inputs. Each input is a usize that represents the index of the input nodes.
    inputs: Vec<usize>,
    /// Gate output. A usize that represents the index of the output node.
    output: usize,
}

impl Component for BinaryGate {
    fn get_inputs(&self) -> Vec<usize> {
        self.inputs.clone()
    }

    fn get_outputs(&self) -> Vec<usize> {
        vec![self.output]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuit_generic::circuit::{CircuitBuilder, CircuitError};

    #[test]
    fn test_reorder() {
        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<BinaryGate>::new();

        // Define gates in the correct order
        let gate1 = BinaryGate {
            inputs: vec![0, 1],
            output: 2,
        };
        let gate2 = BinaryGate {
            inputs: vec![3, 4],
            output: 5,
        };
        let gate3 = BinaryGate {
            inputs: vec![2, 5],
            output: 6,
        };
        let gate4 = BinaryGate {
            inputs: vec![2, 6],
            output: 7,
        };
        let gate5 = BinaryGate {
            inputs: vec![8, 9],
            output: 10,
        };
        let gate6 = BinaryGate {
            inputs: vec![10, 7],
            output: 11,
        };

        // Add gates in a random order
        circuit_builder
            .add_gate(gate6)
            .add_gate(gate3)
            .add_gate(gate1)
            .add_gate(gate5)
            .add_gate(gate4)
            .add_gate(gate2);

        // Build circuit
        let circuit = circuit_builder.build();
        assert!(
            circuit.is_ok(),
            "Failed to build circuit: {:?}",
            circuit.err()
        );
        let circuit = circuit.unwrap();
        let gates = circuit.gates();

        // Verify topological order
        assert_eq!(
            gates[0].get_outputs(),
            vec![2],
            "First gate outputs mismatch" // Gate 1
        );
        assert_eq!(
            gates[1].get_outputs(),
            vec![10],
            "Second gate outputs mismatch" // Gate 5
        );
        assert_eq!(
            gates[2].get_outputs(),
            vec![5],
            "Third gate outputs mismatch" // Gate 2
        );
        assert_eq!(
            gates[3].get_outputs(),
            vec![6],
            "Fourth gate outputs mismatch" // Gate 3
        );
        assert_eq!(
            gates[4].get_outputs(),
            vec![7],
            "Fifth gate outputs mismatch" // Gate 4
        );
        assert_eq!(
            gates[5].get_outputs(),
            vec![11],
            "Sixth gate outputs mismatch" // Gate 6
        );
    }

    #[test]
    fn test_reorder_with_cycle() {
        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<BinaryGate>::new();

        // Define gates in the correct order
        let gate1 = BinaryGate {
            inputs: vec![0, 1],
            output: 2,
        };
        let gate2 = BinaryGate {
            inputs: vec![3, 4],
            output: 5,
        };
        let gate3 = BinaryGate {
            inputs: vec![2, 5],
            output: 6,
        };
        let gate4 = BinaryGate {
            inputs: vec![2, 6],
            output: 7,
        };
        let gate5 = BinaryGate {
            inputs: vec![8, 9],
            output: 10,
        };
        let gate6 = BinaryGate {
            inputs: vec![10, 7],
            output: 11,
        };
        let cycle_gate = BinaryGate {
            inputs: vec![11],
            output: 0,
        };

        // Add gates in the wrong order
        circuit_builder
            .add_gate(gate6)
            .add_gate(gate3)
            .add_gate(gate1)
            .add_gate(gate5)
            .add_gate(gate4)
            .add_gate(gate2)
            .add_gate(cycle_gate);

        // Build circuit should fail due to cycle
        let circuit = circuit_builder.build();
        assert!(circuit.is_err(), "Expected cycle detection error");
        assert_eq!(
            circuit.unwrap_err(),
            CircuitError::CycleDetected,
            "Unexpected error type"
        );
    }
}
