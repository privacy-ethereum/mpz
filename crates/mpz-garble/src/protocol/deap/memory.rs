use mpz_circuits::types::{Value, ValueType};

use crate::{config::Visibility, value::ValueRef, Memory, MemoryError};

use super::DEAP;

impl Memory for DEAP {
    fn new_input_with_type(
        &self,
        id: &str,
        typ: ValueType,
        visibility: Visibility,
    ) -> Result<ValueRef, MemoryError> {
        let value_ref = self.state().memory.new_input(id, typ.clone(), visibility)?;
        self.gen.generate_input_encoding(&value_ref, &typ);
        Ok(value_ref)
    }

    fn new_output_with_type(&self, id: &str, typ: ValueType) -> Result<ValueRef, MemoryError> {
        self.state().memory.new_output(id, typ)
    }

    fn assign(&self, value_ref: &ValueRef, value: impl Into<Value>) -> Result<(), MemoryError> {
        self.state().memory.assign(value_ref, value.into())
    }

    fn assign_by_id(&self, id: &str, value: impl Into<Value>) -> Result<(), MemoryError> {
        let mut state = self.state();
        let value_ref = state
            .memory
            .get_ref_by_id(id)
            .ok_or_else(|| MemoryError::Undefined(id.to_string()))?
            .clone();
        state.memory.assign(&value_ref, value.into())
    }

    fn get_value(&self, id: &str) -> Option<ValueRef> {
        self.state().memory.get_ref_by_id(id).cloned()
    }

    fn get_value_type(&self, value_ref: &ValueRef) -> ValueType {
        self.state().memory.get_value_type(value_ref)
    }

    fn get_value_type_by_id(&self, id: &str) -> Option<ValueType> {
        let state = self.state();
        let value_ref = state.memory.get_ref_by_id(id)?;
        Some(state.memory.get_value_type(value_ref))
    }
}
