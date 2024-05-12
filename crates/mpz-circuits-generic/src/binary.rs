//! Binary Module
//!
//! Test module to display an example of a binary circuit representation.

use crate::{
    circuit::CircuitError,
    model::{Component, Executable, Executor},
};

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
    op: BinaryOperation,
}

impl Component for BinaryGate {
    fn get_inputs(&self) -> Vec<usize> {
        self.inputs.clone()
    }

    fn get_outputs(&self) -> Vec<usize> {
        vec![self.output]
    }
}

impl<T> Executable<T> for BinaryGate {
    type Error = CircuitError;
}

impl Executor<BinaryValue, BinaryGate> for BinaryGate {
    /// User defined custom execution.
    fn custom_execution(
        &self,
        executable: &BinaryGate,
        memory: &mut [BinaryValue],
    ) -> Result<(), CircuitError> {
        let input_values = executable
            .get_inputs()
            .iter()
            .map(|&idx| memory.get(idx).ok_or(CircuitError::MissingNodeValue(idx)))
            .collect::<Result<Vec<&BinaryValue>, _>>()?;

        if input_values.len() != executable.op.input_count() {
            return Err(CircuitError::InvalidGateInputCount);
        }

        let result = match executable.op {
            BinaryOperation::AND => {
                if *input_values[0] == BinaryValue::One && *input_values[1] == BinaryValue::One {
                    BinaryValue::One
                } else {
                    BinaryValue::Zero
                }
            }
            BinaryOperation::NOT => {
                if *input_values[0] == BinaryValue::Zero {
                    BinaryValue::One
                } else {
                    BinaryValue::Zero
                }
            }
            BinaryOperation::XOR => {
                if *input_values[0] != *input_values[1] {
                    BinaryValue::One
                } else {
                    BinaryValue::Zero
                }
            }
        };

        memory[executable.get_outputs()[0]] = result;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{CircuitBuilder, SequentialExecutor};

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
            op: BinaryOperation::AND,
        };
        circuit_builder.add_gate(gate);

        // Build circuit
        let circuit = circuit_builder.build().unwrap();

        // Use the sequential executor for circuit
        let executor = SequentialExecutor;
        executor
            .run_executable(memory.as_mut_slice(), circuit)
            .unwrap();

        // Expected output
        let expected_output_and = BinaryValue::One;

        assert_eq!(memory[2], expected_output_and);
    }
}
