use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_memory_core::{Slice, ToRaw};

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("input count mismatch: expected {expected}, got {actual}")]
    InputCount { expected: usize, actual: usize },
    #[error("input length mismatch: input {idx} expected {expected}, got {actual}")]
    InputLength {
        idx: usize,
        expected: usize,
        actual: usize,
    },
}

#[derive(Debug)]
pub struct CallBuilder {
    circ: Arc<Circuit>,
    inputs: Vec<Slice>,
}

impl CallBuilder {
    pub fn new(circ: Arc<Circuit>) -> Self {
        let input_len = circ.inputs().len();
        Self {
            circ,
            inputs: Vec::with_capacity(input_len),
        }
    }

    pub fn arg<T: ToRaw>(mut self, arg: T) -> Self {
        self.inputs.push(arg.to_raw());
        self
    }

    pub fn build(self) -> Result<Call, CallError> {
        if self.circ.inputs().len() != self.inputs.len() {
            return Err(CallError::InputCount {
                expected: self.circ.inputs().len(),
                actual: self.inputs.len(),
            });
        }

        for (idx, (slice, input)) in self.inputs.iter().zip(self.circ.inputs()).enumerate() {
            if slice.len() != input.len() {
                return Err(CallError::InputLength {
                    idx,
                    expected: input.len(),
                    actual: slice.len(),
                });
            }
        }

        Ok(Call {
            circ: self.circ,
            inputs: self.inputs,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Call {
    circ: Arc<Circuit>,
    inputs: Vec<Slice>,
}

impl Call {
    /// Creates a new call builder.
    pub fn new(circ: Arc<Circuit>) -> CallBuilder {
        CallBuilder::new(circ)
    }

    /// Returns the circuit.
    pub fn circ(&self) -> &Circuit {
        &self.circ
    }

    /// Returns the inputs.
    pub fn inputs(&self) -> &[Slice] {
        &self.inputs
    }

    /// Consumes the call and returns the circuit and inputs.
    pub fn into_parts(self) -> (Arc<Circuit>, Vec<Slice>) {
        (self.circ, self.inputs)
    }
}
