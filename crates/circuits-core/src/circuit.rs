use std::ops::Range;

use crate::components::Gate;

/// An error that can occur when performing operations with a circuit.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum CircuitError {
    #[error("Invalid number of wires: expected {0}, got {1}")]
    InvalidWireCount(usize, usize),
    #[error("Invalid input length: expected {expected}, got {actual}")]
    InvalidInputLength { expected: usize, actual: usize },
    #[error("Invalid output length: expected {expected}, got {actual}")]
    InvalidOutputLength { expected: usize, actual: usize },
}

/// A binary circuit.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Circuit {
    pub(crate) inputs: Range<usize>,
    pub(crate) outputs: Range<usize>,
    pub(crate) gates: Vec<Gate>,
    pub(crate) feed_count: usize,

    pub(crate) and_count: usize,
    pub(crate) xor_count: usize,
}

impl Circuit {
    /// Returns the inputs.
    pub fn inputs(&self) -> Range<usize> {
        self.inputs.clone()
    }

    /// Returns the outputs.
    pub fn outputs(&self) -> Range<usize> {
        self.outputs.clone()
    }

    /// Returns a reference to the gates of the circuit.
    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }

    /// Returns the number of feeds in the circuit.
    pub fn feed_count(&self) -> usize {
        self.feed_count
    }

    /// Returns the number of AND gates in the circuit.
    pub fn and_count(&self) -> usize {
        self.and_count
    }

    /// Returns the number of XOR gates in the circuit.
    pub fn xor_count(&self) -> usize {
        self.xor_count
    }

    /// Evaluate the circuit using the provided wires.
    ///
    /// It is the callers responsibility to ensure the input wires are set.
    pub fn evaluate_raw(&self, wires: &mut [bool]) -> Result<(), CircuitError> {
        if wires.len() != self.feed_count {
            return Err(CircuitError::InvalidWireCount(self.feed_count, wires.len()));
        }

        for gate in self.gates.iter() {
            match gate {
                Gate::Xor { x, y, z } => {
                    let x = wires[x.id];
                    let y = wires[y.id];

                    wires[z.id] = x ^ y;
                }
                Gate::And { x, y, z } => {
                    let x = wires[x.id];
                    let y = wires[y.id];

                    wires[z.id] = x & y;
                }
                Gate::Inv { x, z } => {
                    let x = wires[x.id];

                    wires[z.id] = !x;
                }
                Gate::Id { x, z } => {
                    let x = wires[x.id];

                    wires[z.id] = x;
                }
            }
        }

        Ok(())
    }

    /// Evaluate the circuit with the given inputs.
    ///
    /// # Arguments
    ///
    /// * `values` - The inputs to the circuit
    ///
    /// # Returns
    ///
    /// The outputs of the circuit.
    pub fn evaluate(
        &self,
        input: impl IntoIterator<Item = bool>,
    ) -> Result<Vec<bool>, CircuitError> {
        let mut input = input.into_iter();
        let mut feeds: Vec<bool> = vec![false; self.feed_count];

        for i in self.inputs.clone() {
            let Some(value) = input.next() else {
                return Err(CircuitError::InvalidInputLength {
                    expected: self.inputs.len(),
                    actual: i,
                });
            };

            feeds[i] = value;
        }

        self.evaluate_raw(&mut feeds)?;

        Ok(feeds[self.outputs.clone()].to_vec())
    }
}

impl IntoIterator for Circuit {
    type Item = Gate;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.gates.into_iter()
    }
}
