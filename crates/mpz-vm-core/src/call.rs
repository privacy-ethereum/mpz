use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_memory_core::{Slice, ToRaw};

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("input length mismatch: expected {expected}, got {actual}")]
    InputLength { expected: usize, actual: usize },
}

#[derive(Debug)]
pub struct CallBuilder {
    circ: Arc<Circuit>,
    inputs: Vec<Slice>,
}

impl CallBuilder {
    /// Creates a new call builder.
    pub fn new(circ: Arc<Circuit>) -> Self {
        Self {
            circ,
            inputs: Vec::new(),
        }
    }

    /// Adds an argument to the call.
    pub fn arg<T: ToRaw>(mut self, arg: T) -> Self {
        self.inputs.push(arg.to_raw());
        self
    }

    /// Builds the call.
    pub fn build(self) -> Result<Call, CallError> {
        let input_len = self.inputs.iter().map(|s| s.len()).sum();
        if self.circ.inputs().len() != input_len {
            return Err(CallError::InputLength {
                expected: self.circ.inputs().len(),
                actual: input_len,
            });
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
    pub fn builder(circ: Arc<Circuit>) -> CallBuilder {
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
