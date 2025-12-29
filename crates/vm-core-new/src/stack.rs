use crate::{VmError, value::IValue};

/// The operand stack for VM execution.
#[derive(Debug, Default)]
pub struct OperandStack(Vec<IValue>);

impl OperandStack {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, value: IValue) {
        self.0.push(value);
    }

    pub fn pop(&mut self) -> Result<IValue, VmError> {
        self.0.pop().ok_or(VmError::StackUnderflow)
    }

    pub fn last(&self) -> Result<&IValue, VmError> {
        self.0.last().ok_or(VmError::StackUnderflow)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Peek at the value at the given depth from the top (0 = top).
    pub fn peek(&self, depth: usize) -> Result<&IValue, VmError> {
        let len = self.0.len();
        if depth >= len {
            return Err(VmError::StackUnderflow);
        }
        Ok(&self.0[len - 1 - depth])
    }
}
