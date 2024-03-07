//! Types associated with values in MPC.

use std::sync::Arc;

use mpz_core::utils::blake3;

/// A unique ID for a value.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct ValueId(Arc<String>);

impl ValueId {
    /// Create a new value ID.
    pub fn new(id: &str) -> Self {
        Self(Arc::new(id.to_string()))
    }

    /// Returns a new value ID with the provided ID appended.
    pub fn append_id(&self, id: &str) -> Self {
        Self::new(&format!("{}/{}", self.0, id))
    }

    /// Returns a new value ID with the provided counter appended.
    pub fn append_counter(&self, counter: usize) -> Self {
        Self::new(&format!("{}/{}", self.0, counter))
    }

    /// Returns the u64 representation of the value ID.
    ///
    /// # Warning
    ///
    /// The internal representation for this type is a `u64` and is computed using a hash function.
    /// As such, it is not guaranteed to be unique and collisions may occur. Contexts using these
    /// values should be aware of this and handle collisions appropriately.
    pub fn to_u64(&self) -> u64 {
        let hash = blake3(self.0.as_bytes());
        u64::from_be_bytes(hash[..8].try_into().unwrap())
    }
}

impl AsRef<str> for ValueId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A reference to an array value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArrayRef {
    ids: Vec<ValueId>,
}

impl ArrayRef {
    /// Creates a new array reference.
    ///
    /// # Invariants
    ///
    /// The outer context must enforce the following invariants:
    ///
    ///  * The array must have at least one value.
    ///  * All values in the array must have the same type.
    pub(crate) fn new(ids: Vec<ValueId>) -> Self {
        assert!(!ids.is_empty(), "cannot create an array with no values");

        Self { ids }
    }

    /// Returns the value IDs.
    pub(crate) fn ids(&self) -> &[ValueId] {
        &self.ids
    }

    /// Returns the number of values.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.ids.len()
    }
}

/// A reference to a value.
///
/// Every single value is assigned a unique ID. Whereas, arrays are
/// collections of values, and do not have their own ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum ValueRef {
    /// A single value.
    Value { id: ValueId },
    /// A reference to an array of values.
    Array(ArrayRef),
}

impl ValueRef {
    /// Returns the number of values.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            ValueRef::Value { .. } => 1,
            ValueRef::Array(values) => values.ids.len(),
        }
    }

    /// Returns a new value reference with the provided ID appended.
    ///
    /// If the value is an array, then the ID will be appended to each element.
    pub fn append_id(&self, id: &str) -> Self {
        match self {
            ValueRef::Value { id: value_id } => ValueRef::Value {
                id: value_id.append_id(id),
            },
            ValueRef::Array(values) => ValueRef::Array(ArrayRef {
                ids: values
                    .ids
                    .iter()
                    .map(|value_id| value_id.append_id(id))
                    .collect(),
            }),
        }
    }

    /// Returns `true` if the value is an array.
    pub fn is_array(&self) -> bool {
        matches!(self, ValueRef::Array(_))
    }

    /// Returns an iterator of the value IDs.
    pub fn iter(&self) -> ValueRefIter<'_> {
        match self {
            ValueRef::Value { id } => ValueRefIter::Value(std::iter::once(id)),
            ValueRef::Array(values) => ValueRefIter::Array(values.ids.iter()),
        }
    }
}

/// An iterator over value IDs of a reference.
pub enum ValueRefIter<'a> {
    /// A single value.
    Value(std::iter::Once<&'a ValueId>),
    /// An array of values.
    Array(std::slice::Iter<'a, ValueId>),
}

impl<'a> Iterator for ValueRefIter<'a> {
    type Item = &'a ValueId;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ValueRefIter::Value(iter) => iter.next(),
            ValueRefIter::Array(iter) => iter.next(),
        }
    }
}

/// References to the inputs and outputs of a circuit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CircuitRefs {
    pub(crate) inputs: Vec<ValueRef>,
    pub(crate) outputs: Vec<ValueRef>,
}
