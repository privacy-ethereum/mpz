//! Sorting tests.
//!
//! Test the topological sorting of the gates in the circuit.

use mpz_circuit_generic::{Component, Node};
use std::iter;

#[derive(Debug)]
pub struct Gate {
    inputs: Vec<Node<u32>>,
    output: Node<u32>,
}

impl Component for Gate {
    fn get_inputs(&self) -> impl Iterator<Item = &Node<u32>> {
        self.inputs.iter()
    }

    fn get_outputs(&self) -> impl Iterator<Item = &Node<u32>> {
        iter::once(&self.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuit_generic::{CircuitBuilder, CircuitBuilderError};

    #[test]
    fn test_gates_reorder() {
        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<Gate>::new();

        // Define gates in the correct order
        let gate1 = Gate {
            inputs: vec![Node::new(0), Node::new(1)],
            output: Node::new(2),
        };
        let gate2 = Gate {
            inputs: vec![Node::new(3), Node::new(4)],
            output: Node::new(5),
        };
        let gate3 = Gate {
            inputs: vec![Node::new(2), Node::new(5)],
            output: Node::new(6),
        };
        let gate4 = Gate {
            inputs: vec![Node::new(2), Node::new(6)],
            output: Node::new(7),
        };
        let gate5 = Gate {
            inputs: vec![Node::new(8), Node::new(9)],
            output: Node::new(10),
        };
        let gate6 = Gate {
            inputs: vec![Node::new(10), Node::new(7)],
            output: Node::new(11),
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
            gates[0].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(2)],
            "First gate outputs mismatch" // Gate 1
        );
        assert_eq!(
            gates[1].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(10)],
            "Second gate outputs mismatch" // Gate 5
        );
        assert_eq!(
            gates[2].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(5)],
            "Third gate outputs mismatch" // Gate 2
        );
        assert_eq!(
            gates[3].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(6)],
            "Fourth gate outputs mismatch" // Gate 3
        );
        assert_eq!(
            gates[4].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(7)],
            "Fifth gate outputs mismatch" // Gate 4
        );
        assert_eq!(
            gates[5].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(11)],
            "Sixth gate outputs mismatch" // Gate 6
        );
    }

    #[test]
    fn test_cycle_detection() {
        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<Gate>::new();

        // Define gates
        let gate1 = Gate {
            inputs: vec![Node::new(0), Node::new(1)],
            output: Node::new(2),
        };
        let gate2 = Gate {
            inputs: vec![Node::new(2), Node::new(3)],
            output: Node::new(4),
        };
        let cycle_gate = Gate {
            inputs: vec![Node::new(4)],
            output: Node::new(0),
        };

        // Add gates
        circuit_builder
            .add_gate(gate1)
            .add_gate(gate2)
            .add_gate(cycle_gate);

        // Expect build to fail
        let circuit = circuit_builder.build();
        assert!(circuit.is_err(), "Expected cycle detection error");
        assert_eq!(
            circuit.unwrap_err(),
            CircuitBuilderError::CycleDetected,
            "Unexpected error type"
        );
    }

    #[test]
    fn test_disconnected_gate() {
        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<Gate>::new();

        // Define gates, with one gate disconnected
        let gate1 = Gate {
            inputs: vec![Node::new(0), Node::new(1)],
            output: Node::new(2),
        };
        let gate2 = Gate {
            inputs: vec![Node::new(3), Node::new(4)],
            output: Node::new(5),
        };
        let gate3 = Gate {
            inputs: vec![Node::new(2), Node::new(5)],
            output: Node::new(6),
        };
        let disconnected_gate = Gate {
            inputs: vec![Node::new(7), Node::new(8)],
            output: Node::new(9),
        };

        // Add gates including the disconnected gate
        circuit_builder
            .add_gate(gate1)
            .add_gate(gate2)
            .add_gate(gate3)
            .add_gate(disconnected_gate);

        // Build circuit
        let circuit = circuit_builder.build();
        assert!(
            circuit.is_ok(),
            "Failed to build circuit: {:?}",
            circuit.err()
        );
        let circuit = circuit.unwrap();
        let gates = circuit.gates();

        // Verify order
        // Gate 1 and 2 were added first and have in_degree 0 so they will be processed right away
        // The disconnected gate also has in_degree 0 so it will be put next to them
        // Gate 3 will be processed last for having in_degree > 0
        assert_eq!(
            gates[0].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(2)],
            "First gate outputs mismatch" // Gate 1
        );
        assert_eq!(
            gates[1].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(5)],
            "Second gate outputs mismatch" // Gate 2
        );
        assert_eq!(
            gates[2].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(9)],
            "Third gate outputs mismatch" // Disconnected Gate
        );
        assert_eq!(
            gates[3].get_outputs().collect::<Vec<_>>(),
            vec![&Node::new(6)],
            "Fourth gate outputs mismatch" // Gate 3
        );
    }
}
