//! Binary Module
//!
//! Test module to display an example of a binary circuit representation.

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

impl BinaryOperation {
    /// Returns the number of inputs the operation requires.
    pub fn input_count(&self) -> usize {
        match self {
            Self::AND | Self::XOR => 2,
            Self::NOT => 1,
        }
    }
}

/// Binary gate.
#[derive(Debug, Clone)]
pub struct BinaryGate {
    /// Gate inputs. Each input is a usize that represents the index of the input nodes.
    inputs: Vec<usize>,
    /// Gate output. A usize that represents the index of the output node.
    output: usize,
    /// Gate operation.
    _op: BinaryOperation,
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
    fn test_simple_acyclic_circuit() {
        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<BinaryGate>::new();

        // Add gates
        let gate1 = BinaryGate {
            inputs: vec![0, 1],
            output: 2,
            _op: BinaryOperation::AND,
        };
        let gate2 = BinaryGate {
            inputs: vec![2],
            output: 3,
            _op: BinaryOperation::NOT,
        };

        circuit_builder.add_gate(gate2).add_gate(gate1);

        // Build circuit
        let circuit = circuit_builder.build();
        assert!(circuit.is_ok(), "Failed to build circuit: {:?}", circuit.err());
        let circuit = circuit.unwrap();
        let gates = circuit.gates();

        // Verify topological order
        assert_eq!(gates[0].get_outputs(), vec![2], "First gate outputs mismatch");
        assert_eq!(gates[1].get_outputs(), vec![3], "Second gate outputs mismatch");
    }

    #[test]
    fn test_complex_acyclic_circuit() {
        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<BinaryGate>::new();

        // Add gates
        let gate1 = BinaryGate {
            inputs: vec![0],
            output: 2,
            _op: BinaryOperation::NOT,
        };
        let gate2 = BinaryGate {
            inputs: vec![1, 2],
            output: 3,
            _op: BinaryOperation::XOR,
        };
        let gate3 = BinaryGate {
            inputs: vec![2],
            output: 4,
            _op: BinaryOperation::NOT,
        };
        let gate4 = BinaryGate {
            inputs: vec![3, 4],
            output: 5,
            _op: BinaryOperation::AND,
        };

        circuit_builder
            .add_gate(gate1)
            .add_gate(gate3)
            .add_gate(gate2)
            .add_gate(gate4);

        // Build circuit
        let circuit = circuit_builder.build();
        assert!(circuit.is_ok(), "Failed to build circuit: {:?}", circuit.err());
        let circuit = circuit.unwrap();
        let gates = circuit.gates();

        // Verify topological order
        assert_eq!(gates[0].get_outputs(), vec![2], "First gate outputs mismatch");
        assert_eq!(gates[1].get_outputs(), vec![4], "Second gate outputs mismatch");
        assert_eq!(gates[2].get_outputs(), vec![3], "Third gate outputs mismatch");
        assert_eq!(gates[3].get_outputs(), vec![5], "Fourth gate outputs mismatch");
    }

    #[test]
    fn test_cycle_detection() {
        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<BinaryGate>::new();

        // Add gates
        let gate1 = BinaryGate {
            inputs: vec![0],
            output: 1,
            _op: BinaryOperation::NOT,
        };
        let gate2 = BinaryGate {
            inputs: vec![1],
            output: 2,
            _op: BinaryOperation::NOT,
        };
        let gate3 = BinaryGate {
            inputs: vec![2],
            output: 0, // This creates a cycle
            _op: BinaryOperation::NOT,
        };

        circuit_builder.add_gate(gate1).add_gate(gate2).add_gate(gate3);

        // Build circuit should fail due to cycle
        let circuit = circuit_builder.build();
        assert!(circuit.is_err(), "Expected cycle detection error");
        assert_eq!(circuit.unwrap_err(), CircuitError::CycleDetected, "Unexpected error type");
    }
}