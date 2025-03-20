use std::ops::Add;

use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};

use crate::{
    correlated::{Delta, Key, Mac},
    store::{Store, StoreError},
    RangeSet, Slice,
};

type Result<T> = core::result::Result<T, AuthBitStoreError>;

/// A store for authenticated bits, consisting of a bool value, a MAC, and a Key.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuthBit {
    value: bool,
    mac: Mac,
    key: Key,
}

impl AuthBit {
    /// Creates a new authenticated bit.
    #[inline]
    pub fn new(value: bool, mac: Mac, key: Key) -> Self {
        Self { value, mac, key }
    }

    /// Returns the value of the authenticated bit.
    #[inline]
    pub fn value(&self) -> bool {
        self.value
    }

    /// Returns the MAC of the authenticated bit.
    #[inline]
    pub fn mac(&self) -> &Mac {
        &self.mac
    }

    /// Returns the key of the authenticated bit.
    #[inline]
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Sets the value of the authenticated bit.
    #[inline]
    pub fn set_value(&mut self, value: bool) {
        self.value = value;
    }
}

/// A linear store which manages authenticated bits.
#[derive(Debug, Clone, Default)]
pub struct AuthBitStore {
    bits: Store<AuthBit>,
}

impl AuthBitStore {
    /// Creates a new authenticated bit store.
    #[inline]
    pub fn new() -> Self {
        Self {
            bits: Store::default(),
        }
    }

    /// Returns whether all the authenticated bits are set.
    #[inline]
    pub fn is_set(&self, slice: Slice) -> bool {
        self.bits.is_set(slice)
    }

    /// Returns the ranges which have authenticated bits set.
    #[inline]
    pub fn set_ranges(&self) -> &RangeSet {
        self.bits.set_ranges()
    }

    /// Allocates uninitialized memory.
    #[inline]
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.bits.alloc(len)
    }

    /// Allocates memory with the given authenticated bits.
    #[inline]
    pub fn alloc_with(&mut self, bits: &[AuthBit]) -> Slice {
        self.bits.alloc_with(bits)
    }

    /// Returns authenticated bits if they are set.
    #[inline]
    pub fn try_get(&self, slice: Slice) -> Result<&[AuthBit]> {
        self.bits.try_get(slice).map_err(From::from)
    }

    /// Sets authenticated bits, returning an error if they are already set.
    #[inline]
    pub fn try_set(&mut self, slice: Slice, bits: &[AuthBit]) -> Result<()> {
        self.bits.try_set(slice, bits).map_err(From::from)
    }

    /// Returns the values of the authenticated bits if they are set.
    pub fn try_get_values(&self, slice: Slice) -> Result<impl Iterator<Item = bool> + '_> {
        self.bits
            .try_get(slice)
            .map(|bits| bits.iter().map(|bit| bit.value()))
            .map_err(From::from)
    }

    /// Adjusts the authenticated bits for the given range.
    ///
    /// # Panics
    ///
    /// Panics if the data is not the same length as the range.
    pub fn adjust(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        assert_eq!(
            slice.size,
            data.len(),
            "data is not the same length as the range"
        );

        self.bits
            .try_get_slice_mut(slice)?
            .iter_mut()
            .zip(data)
            .for_each(|(bit, value)| {
                bit.set_value(*value);
            });

        Ok(())
    }
}

/// Error for [`AuthBitStore`].
#[derive(Debug, thiserror::Error)]
pub enum AuthBitStoreError {
    #[error("invalid slice: {}", .0)]
    InvalidSlice(Slice),
    #[error("authenticated bits are not initialized: {}", .0)]
    Uninit(Slice),
    #[error("authenticated bits are already set: {}", .0)]
    AlreadySet(Slice),
}

impl From<StoreError> for AuthBitStoreError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::InvalidSlice(slice) => Self::InvalidSlice(slice),
            StoreError::Uninit(slice) => Self::Uninit(slice),
            StoreError::AlreadySet(slice) => Self::AlreadySet(slice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust() {
        let mut store = AuthBitStore::new();
        
        let auth_bits = vec![
            AuthBit::new(false, Mac::default(), Key::default()),
            AuthBit::new(true, Mac::default(), Key::default()),
        ];

        let slice = store.alloc_with(&auth_bits);
        let data = BitVec::from_iter([true, false]);

        store.adjust(slice, &data).unwrap();

        let values = store
            .try_get(slice)
            .unwrap()
            .iter()
            .map(|bit| bit.value())
            .collect::<Vec<_>>();

        assert_eq!(values, vec![true, false]);
    }
}
