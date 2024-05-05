//! Binary Module
//!
//! Test module to display an example of a binary circuit representation.

use crate::circuit::{CircuitError, Evaluate, RepresentedValue};

#[derive(Debug, Copy, Clone, PartialEq)]
/// Binary gate value.
pub enum BinaryValue {
    /// Binary zero.
    Zero,
    /// Binary one.
    One,
}

// Each gate can be performing the same operation multiple times,
// One for each bit of the represented value.
pub type BinaryGateValue = Vec<BinaryValue>;

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
    pub fn input_count(&self) -> usize {
        match self {
            Self::AND | Self::XOR => 2,
            Self::NOT => 1,
        }
    }

    pub fn evaluate(&self, inputs: &[&BinaryGateValue]) -> Result<BinaryGateValue, CircuitError> {
        match self {
            Self::AND => Ok(inputs[0]
                .iter()
                .zip(inputs[1])
                .map(|(&a, &b)| {
                    if a == BinaryValue::One && b == BinaryValue::One {
                        BinaryValue::One
                    } else {
                        BinaryValue::Zero
                    }
                })
                .collect()),
            Self::NOT => Ok(inputs[0]
                .iter()
                .map(|&x| {
                    if x == BinaryValue::Zero {
                        BinaryValue::One
                    } else {
                        BinaryValue::Zero
                    }
                })
                .collect()),
            Self::XOR => Ok(inputs[0]
                .iter()
                .zip(inputs[1])
                .map(|(&a, &b)| {
                    if a != b {
                        BinaryValue::One
                    } else {
                        BinaryValue::Zero
                    }
                })
                .collect()),
        }
    }
}

/// Binary circuit representation value.
/// Used as interface for the circuit
#[derive(Debug, PartialEq)]
pub enum BinaryCircuitReprValue {
    /// Bool value,
    Bool(bool),
    /// u8 value.
    U8(u8),
}

// Implement RepresentedValue for BinaryCircuitReprValue.
impl RepresentedValue<BinaryGateValue> for BinaryCircuitReprValue {
    fn from_value(value: &BinaryGateValue) -> Result<Self, CircuitError> {
        match value.len() {
            1 => {
                let bit = value[0];
                Ok(BinaryCircuitReprValue::Bool(bit == BinaryValue::One))
            }
            8 => {
                let byte = value.iter().fold(0, |acc, &bit| {
                    (acc << 1) | (if bit == BinaryValue::One { 1 } else { 0 })
                });
                Ok(BinaryCircuitReprValue::U8(byte as u8))
            }
            _ => Err(CircuitError::ConversionError),
        }
    }

    fn to_value(&self) -> Result<BinaryGateValue, CircuitError> {
        match *self {
            BinaryCircuitReprValue::Bool(b) => Ok(vec![if b {
                BinaryValue::One
            } else {
                BinaryValue::Zero
            }]),
            BinaryCircuitReprValue::U8(byte) => {
                let bits = (0..8)
                    .rev()
                    .map(|i| {
                        if byte & (1 << i) != 0 {
                            BinaryValue::One
                        } else {
                            BinaryValue::Zero
                        }
                    })
                    .collect();
                Ok(bits)
            }
        }
    }
}

/// Binary gate.
pub struct BinaryGate {
    /// Gate inputs. Each input is a usize that represents the index of the input gate.
    inputs: Vec<usize>,
    /// Gate output. A usize that represents the index of the output gate.
    output: usize,
    /// Gate operation.
    op: BinaryOperation,
}

impl Evaluate<BinaryGateValue> for BinaryGate {
    fn evaluate(&self, feeds: &mut Vec<Option<BinaryGateValue>>) -> Result<(), CircuitError> {
        let input_values: Vec<_> = self
            .inputs
            .iter()
            .map(|&idx| {
                feeds
                    .get(idx)
                    .and_then(|v| v.as_ref())
                    .ok_or(CircuitError::MissingNodeValue(idx))
            })
            .collect::<Result<_, _>>()?;

        if input_values.len() != self.op.input_count() {
            return Err(CircuitError::InvalidGateInputCount(
                self.op.input_count(),
                input_values.len(),
            ));
        }

        let result = self.op.evaluate(&input_values)?;

        // Resize the feeds vector if the output index is out of bounds
        // This is the only reason that evaluate receives a vec instead of a slice.
        if feeds.get_mut(self.output).is_none() {
            feeds.resize(self.output + 1, None);
        }

        if let Some(output) = feeds.get_mut(self.output) {
            *output = Some(result);
        } else {
            return Err(CircuitError::OutputIndexOutOfRange(self.output));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::Circuit;

    #[test]
    fn test_circuit() {
        // Initialize the circuit
        let mut circuit = Circuit::<BinaryCircuitReprValue, BinaryGate, BinaryGateValue>::new();

        // Add gates
        let gate = BinaryGate {
            inputs: vec![0, 1],
            output: 2,
            op: BinaryOperation::AND,
        };
        circuit.add_gate(gate);

        // Prepare inputs
        let input_a: u8 = 0b10101010;
        let input_b: u8 = 0b00001111;

        let repr_input_a = BinaryCircuitReprValue::U8(input_a);
        let repr_input_b = BinaryCircuitReprValue::U8(input_b);

        // Add inputs to the circuit
        circuit.add_input(repr_input_a);
        circuit.add_input(repr_input_b);

        // Define output index
        circuit.add_output(2);

        // Expected output
        let expected_output: u8 = 0b00001010;
        let repr_expected_output = BinaryCircuitReprValue::U8(expected_output);

        // Run the circuit and verify the outputs
        let output_values = circuit.run().unwrap();

        // Check if the number of outputs and their values are as expected
        assert_eq!(output_values.len(), 1);
        assert_eq!(output_values[0], repr_expected_output);
    }
}
