//! Binary Module
//!
//! Test module to display an example of a binary circuit representation.

use mpz_circuit_generic::model::Component;

#[derive(Debug, Copy, Clone, PartialEq)]
/// Binary gate value.
pub enum BinaryValue {
    /// Binary zero.
    Zero,
    /// Binary one.
    One,
}

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
    use mpz_circuit_generic::circuit::CircuitBuilder;

    #[test]
    fn test_circuit() {
        // Build memory
        let mut memory: Vec<BinaryValue> = Vec::with_capacity(3);

        // Add inputs to memory
        let input_a = BinaryValue::One;
        let input_b = BinaryValue::One;

        memory.push(input_a);
        memory.push(input_b);
        memory.push(BinaryValue::Zero); // Output

        // Setup circuit builder
        let mut circuit_builder = CircuitBuilder::<BinaryGate>::new();

        // Add gate
        let gate = BinaryGate {
            inputs: vec![0, 1],
            output: 2,
            _op: BinaryOperation::AND,
        };
        circuit_builder.add_gate(gate);

        // Build circuit
        assert!(circuit_builder.build().is_ok());
    }
}
