use std::collections::{HashMap, HashSet};

use mpz_circuits::types::{Value, ValueType};
use mpz_garble_core::{encoding_state::LabelState, EncodedValue};

use crate::{
    config::Visibility,
    value::{ArrayRef, ValueId, ValueRef},
    AssignmentError, MemoryError,
};

/// Collection of assigned values.
#[derive(Debug)]
pub struct AssignedValues {
    /// Public values.
    pub public: Vec<(ValueId, Value)>,
    /// Private values.
    pub private: Vec<(ValueId, Value)>,
    /// Blind values.
    pub blind: Vec<(ValueId, ValueType)>,
}

enum AssignedValue {
    Public(Value),
    Private(Value),
    Blind(ValueType),
}

enum ValueDetails {
    Input {
        typ: ValueType,
        visibility: Visibility,
    },
    Output {
        typ: ValueType,
    },
}

impl ValueDetails {
    fn typ(&self) -> &ValueType {
        match self {
            ValueDetails::Input { typ, .. } => typ,
            ValueDetails::Output { typ } => typ,
        }
    }
}

/// A memory for storing values.
#[derive(Default)]
pub struct ValueMemory {
    /// IDs for each reference
    id_to_ref: HashMap<String, ValueRef>,
    /// References for each ID
    ref_to_id: HashMap<ValueRef, String>,
    /// Details for each value
    details: HashMap<ValueId, ValueDetails>,
    /// Values that have been assigned and blind values
    assigned: HashSet<ValueId>,
    /// Buffer containing assigned values
    assigned_buffer: HashMap<ValueId, AssignedValue>,
}

opaque_debug::implement!(ValueMemory);

impl ValueMemory {
    /// Adds a new input value to the memory.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the value.
    /// * `typ` - The type of the value.
    /// * `visibility` - The visibility of the value.
    pub fn new_input(
        &mut self,
        id: &str,
        typ: ValueType,
        visibility: Visibility,
    ) -> Result<ValueRef, MemoryError> {
        let value_id = ValueId::new(id);
        let value_ref = if let ValueType::Array(typ, len) = typ {
            let typ = *typ;
            let mut ids = Vec::with_capacity(len);
            for i in 0..len {
                let elem_id = value_id.append_counter(i);

                if self.details.contains_key(&elem_id) {
                    return Err(MemoryError::DuplicateValueId(elem_id));
                }

                self.details.insert(
                    elem_id.clone(),
                    ValueDetails::Input {
                        typ: typ.clone(),
                        visibility,
                    },
                );
                ids.push(elem_id);
            }

            if let Visibility::Blind = visibility {
                for id in &ids {
                    self.assigned.insert(id.clone());
                    self.assigned_buffer
                        .insert(id.clone(), AssignedValue::Blind(typ.clone()));
                }
            }

            ValueRef::Array(ArrayRef::new(ids))
        } else {
            if self.details.contains_key(&value_id) {
                return Err(MemoryError::DuplicateValueId(value_id));
            }

            self.details.insert(
                value_id.clone(),
                ValueDetails::Input {
                    typ: typ.clone(),
                    visibility,
                },
            );

            if let Visibility::Blind = visibility {
                self.assigned.insert(value_id.clone());
                self.assigned_buffer
                    .insert(value_id.clone(), AssignedValue::Blind(typ.clone()));
            }

            ValueRef::Value { id: value_id }
        };

        self.id_to_ref.insert(id.to_string(), value_ref.clone());
        self.ref_to_id.insert(value_ref.clone(), id.to_string());

        Ok(value_ref)
    }

    /// Adds a new output value to the memory.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the value.
    /// * `typ` - The type of the value.
    pub fn new_output(&mut self, id: &str, typ: ValueType) -> Result<ValueRef, MemoryError> {
        let value_id = ValueId::new(id);
        let value_ref = if let ValueType::Array(typ, len) = typ {
            let typ = *typ;
            let mut ids = Vec::with_capacity(len);
            for i in 0..len {
                let elem_id = value_id.append_counter(i);

                if self.details.contains_key(&elem_id) {
                    return Err(MemoryError::DuplicateValueId(elem_id));
                }

                self.details
                    .insert(elem_id.clone(), ValueDetails::Output { typ: typ.clone() });

                ids.push(elem_id);
            }

            ValueRef::Array(ArrayRef::new(ids))
        } else {
            if self.details.contains_key(&value_id) {
                return Err(MemoryError::DuplicateValueId(value_id));
            }

            self.details
                .insert(value_id.clone(), ValueDetails::Output { typ });

            ValueRef::Value { id: value_id }
        };

        self.id_to_ref.insert(id.to_string(), value_ref.clone());
        self.ref_to_id.insert(value_ref.clone(), id.to_string());

        Ok(value_ref)
    }

    /// Assigns a value to a value reference.
    ///
    /// # Arguments
    ///
    /// * `value_ref` - The value reference.
    /// * `value` - The value to assign.
    pub fn assign(&mut self, value_ref: &ValueRef, value: Value) -> Result<(), MemoryError> {
        match value_ref {
            ValueRef::Array(array) => {
                let elem_details = self
                    .details
                    .get(&array.ids()[0])
                    .expect("value is defined if reference exists");

                let expected_typ =
                    ValueType::Array(Box::new(elem_details.typ().clone()), array.len());
                let actual_typ = value.value_type();
                if expected_typ != actual_typ {
                    Err(AssignmentError::Type {
                        value: value_ref.clone(),
                        expected: expected_typ,
                        actual: actual_typ,
                    })?
                }

                let Value::Array(elems) = value else {
                    unreachable!("value type is checked above");
                };

                for (id, elem) in array.ids().iter().zip(elems) {
                    self.assign(&ValueRef::Value { id: id.clone() }, elem)?;
                }
            }
            ValueRef::Value { id } => {
                let details = self
                    .details
                    .get(id)
                    .expect("value is defined if reference exists");

                let ValueDetails::Input { typ, visibility } = details else {
                    Err(AssignmentError::Output(id.clone()))?
                };

                if typ != &value.value_type() {
                    Err(AssignmentError::Type {
                        value: value_ref.clone(),
                        expected: typ.clone(),
                        actual: value.value_type(),
                    })?
                }

                let value = match visibility {
                    Visibility::Public => AssignedValue::Public(value),
                    Visibility::Private => AssignedValue::Private(value),
                    Visibility::Blind => Err(AssignmentError::BlindInput(id.clone()))?,
                };

                if self.assigned.contains(id) {
                    Err(AssignmentError::Duplicate(id.clone()))?
                }

                self.assigned_buffer.insert(id.clone(), value);
                self.assigned.insert(id.clone());
            }
        }

        Ok(())
    }

    /// Returns a value reference by ID if it exists.
    pub fn get_ref_by_id(&self, id: &str) -> Option<&ValueRef> {
        self.id_to_ref.get(id)
    }

    /// Returns a value ID by reference if it exists.
    pub fn get_id_by_ref(&self, value_ref: &ValueRef) -> Option<&str> {
        self.ref_to_id.get(value_ref).map(|id| id.as_str())
    }

    /// Returns the type of value of a value reference.
    pub fn get_value_type(&self, value_ref: &ValueRef) -> ValueType {
        match value_ref {
            ValueRef::Array(array) => {
                let details = self
                    .details
                    .get(&array.ids()[0])
                    .expect("value is defined if reference exists");

                ValueType::Array(Box::new(details.typ().clone()), array.len())
            }
            ValueRef::Value { id } => self
                .details
                .get(id)
                .expect("value is defined if reference exists")
                .typ()
                .clone(),
        }
    }

    /// Drains assigned values from buffer if they are present.
    ///
    /// Returns a tuple of public, private, and blind values.
    pub fn drain_assigned(&mut self, values: &[ValueRef]) -> AssignedValues {
        let mut public = Vec::new();
        let mut private = Vec::new();
        let mut blind = Vec::new();
        for id in values.iter().flat_map(|value| value.iter()) {
            if let Some(value) = self.assigned_buffer.remove(id) {
                match value {
                    AssignedValue::Public(v) => public.push((id.clone(), v)),
                    AssignedValue::Private(v) => private.push((id.clone(), v)),
                    AssignedValue::Blind(v) => blind.push((id.clone(), v)),
                }
            }
        }

        AssignedValues {
            public,
            private,
            blind,
        }
    }
}

/// A unique ID for an encoding.
///
/// # Warning
///
/// The internal representation for this type is a `u64` and is computed using a hash function.
/// As such, it is not guaranteed to be unique and collisions may occur. Contexts using these
/// IDs should be aware of this and handle collisions appropriately.
///
/// For example, an encoding should never be used for more than one value as this will compromise
/// the security of the MPC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub(crate) struct EncodingId(u64);

impl EncodingId {
    /// Create a new encoding ID.
    pub(crate) fn new(id: u64) -> Self {
        Self(id)
    }
}

impl From<u64> for EncodingId {
    fn from(id: u64) -> Self {
        Self::new(id)
    }
}

/// Errors which can occur when registering an encoding.
#[derive(Debug, thiserror::Error)]
pub enum EncodingMemoryError {
    #[error("encoding for value {0:?} is already defined")]
    DuplicateId(ValueId),
}

/// Memory for encodings.
///
/// This is used to store encodings for values.
///
/// It enforces that an encoding for a value is only set once.
#[derive(Debug)]
pub(crate) struct EncodingMemory<T>
where
    T: LabelState,
{
    encodings: HashMap<EncodingId, EncodedValue<T>>,
}

impl<T> Default for EncodingMemory<T>
where
    T: LabelState,
{
    fn default() -> Self {
        Self {
            encodings: HashMap::new(),
        }
    }
}

impl<T> EncodingMemory<T>
where
    T: LabelState,
{
    /// Set the encoding for a value id.
    pub(crate) fn set_encoding_by_id(
        &mut self,
        id: &ValueId,
        encoding: EncodedValue<T>,
    ) -> Result<(), EncodingMemoryError> {
        let encoding_id = EncodingId::new(id.to_u64());
        if self.encodings.contains_key(&encoding_id) {
            return Err(EncodingMemoryError::DuplicateId(id.clone()));
        }

        self.encodings.insert(encoding_id, encoding);

        Ok(())
    }

    /// Set the encoding for a value.
    ///
    /// # Panics
    ///
    /// Panics if the encoding for the value has already been set, or if the value
    /// type does not match the encoding type.
    pub(crate) fn set_encoding(
        &mut self,
        value: &ValueRef,
        encoding: EncodedValue<T>,
    ) -> Result<(), EncodingMemoryError> {
        let encoding_type = encoding.value_type();
        match (value, encoding) {
            (ValueRef::Value { id }, encoding) => self.set_encoding_by_id(id, encoding)?,
            (ValueRef::Array(array), EncodedValue::Array(encodings))
                if array.len() == encodings.len() =>
            {
                for (id, encoding) in array.ids().iter().zip(encodings) {
                    self.set_encoding_by_id(id, encoding)?
                }
            }
            _ => panic!(
                "value type {:?} does not match encoding type: {:?}",
                value, encoding_type
            ),
        }

        Ok(())
    }

    /// Get the encoding for a value id if it exists.
    pub(crate) fn get_encoding_by_id(&self, id: &ValueId) -> Option<EncodedValue<T>> {
        self.encodings.get(&id.to_u64().into()).cloned()
    }

    /// Get the encoding for a value if it exists.
    ///
    /// # Panics
    ///
    /// Panics if the value is an array and if the type of its elements is not consistent.
    pub(crate) fn get_encoding(&self, value: &ValueRef) -> Option<EncodedValue<T>> {
        match value {
            ValueRef::Value { id, .. } => self.encodings.get(&id.to_u64().into()).cloned(),
            ValueRef::Array(array) => {
                let encodings = array
                    .ids()
                    .iter()
                    .map(|id| self.encodings.get(&id.to_u64().into()).cloned())
                    .collect::<Option<Vec<_>>>()?;

                assert!(
                    encodings
                        .windows(2)
                        .all(|window| window[0].value_type() == window[1].value_type()),
                    "inconsistent element types in array {:?}",
                    value
                );

                Some(EncodedValue::Array(encodings))
            }
        }
    }

    /// Returns whether an encoding is present for a value id.
    pub(crate) fn contains(&self, id: &ValueId) -> bool {
        self.encodings.contains_key(&id.to_u64().into())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;

    use mpz_circuits::types::StaticValueType;
    use mpz_garble_core::{encoding_state, ChaChaEncoder, Encoder};
    use rstest::*;

    #[fixture]
    fn encoder() -> ChaChaEncoder {
        ChaChaEncoder::new([0; 32])
    }

    fn generate_encoding(
        encoder: ChaChaEncoder,
        value: &ValueRef,
        ty: &ValueType,
    ) -> EncodedValue<encoding_state::Full> {
        match (value, ty) {
            (ValueRef::Value { id }, ty) => encoder.encode_by_type(id.to_u64(), ty),
            (ValueRef::Array(array), ValueType::Array(elem_ty, _)) => EncodedValue::Array(
                array
                    .ids()
                    .iter()
                    .map(|id| encoder.encode_by_type(id.to_u64(), elem_ty))
                    .collect(),
            ),
            _ => panic!(),
        }
    }

    #[rstest]
    #[case::bit(PhantomData::<bool>)]
    #[case::u8(PhantomData::<u8>)]
    #[case::u16(PhantomData::<u16>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u128(PhantomData::<u128>)]
    #[case::bit_array(PhantomData::<[bool; 16]>)]
    #[case::u8_array(PhantomData::<[u8; 16]>)]
    #[case::u16_array(PhantomData::<[u16; 16]>)]
    #[case::u32_array(PhantomData::<[u32; 16]>)]
    #[case::u64_array(PhantomData::<[u64; 16]>)]
    #[case::u128_array(PhantomData::<[u128; 16]>)]
    fn test_value_memory_duplicate_fails<T>(#[case] _ty: PhantomData<T>)
    where
        T: StaticValueType + Default + std::fmt::Debug,
    {
        let mut memory = ValueMemory::default();

        let _ = memory
            .new_input("test", T::value_type(), Visibility::Private)
            .unwrap();

        let err = memory
            .new_input("test", T::value_type(), Visibility::Private)
            .unwrap_err();

        assert!(matches!(err, MemoryError::DuplicateValueId(_)));
    }

    #[rstest]
    #[case::bit(PhantomData::<bool>)]
    #[case::u8(PhantomData::<u8>)]
    #[case::u16(PhantomData::<u16>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u64(PhantomData::<u64>)]
    #[case::u128(PhantomData::<u128>)]
    #[case::bit_array(PhantomData::<[bool; 16]>)]
    #[case::u8_array(PhantomData::<[u8; 16]>)]
    #[case::u16_array(PhantomData::<[u16; 16]>)]
    #[case::u32_array(PhantomData::<[u32; 16]>)]
    #[case::u64_array(PhantomData::<[u64; 16]>)]
    #[case::u128_array(PhantomData::<[u128; 16]>)]
    fn test_encoding_memory_set_duplicate_fails<T>(
        encoder: ChaChaEncoder,
        #[case] _ty: PhantomData<T>,
    ) where
        T: StaticValueType + Default + std::fmt::Debug,
    {
        let mut memory = ValueMemory::default();
        let mut full_encoding_memory = EncodingMemory::<encoding_state::Full>::default();
        let mut active_encoding_memory = EncodingMemory::<encoding_state::Active>::default();

        let typ = T::value_type();
        let value = memory
            .new_input("test", typ.clone(), Visibility::Private)
            .unwrap();

        let encoding = generate_encoding(encoder, &value, &typ);

        full_encoding_memory
            .set_encoding(&value, encoding.clone())
            .unwrap();

        let err = full_encoding_memory
            .set_encoding(&value, encoding.clone())
            .unwrap_err();

        assert!(matches!(err, EncodingMemoryError::DuplicateId(_)));

        let encoding = encoding.select(T::default()).unwrap();

        active_encoding_memory
            .set_encoding(&value, encoding.clone())
            .unwrap();

        let err = active_encoding_memory
            .set_encoding(&value, encoding)
            .unwrap_err();

        assert!(matches!(err, EncodingMemoryError::DuplicateId(_)));
    }
}
