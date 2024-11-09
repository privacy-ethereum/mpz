use mpz_core::bitvec::{BitSlice, BitVec};
use utils::range::Subset;

use crate::{Ptr, Slice};

type RangeSet = utils::range::RangeSet<usize>;
type Result<T> = core::result::Result<T, StoreError>;

/// A linear store.
#[derive(Debug, Clone)]
pub struct Store<T> {
    items: Vec<T>,
    set: RangeSet,
}

impl<T> Default for Store<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Store<T> {
    /// Creates a new store.
    #[inline]
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            set: RangeSet::default(),
        }
    }

    /// Creates a new store with the given capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            set: RangeSet::default(),
        }
    }

    /// Returns the length of the store.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns whether the given range is set.
    #[inline]
    pub fn is_set(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.set)
    }

    /// Returns the ranges of set data.
    #[inline]
    pub fn set_ranges(&self) -> &RangeSet {
        &self.set
    }

    /// Returns a slice if it is set.
    #[inline]
    pub fn try_get(&self, slice: Slice) -> Result<&[T]> {
        if slice.to_range().is_subset(&self.set) {
            Ok(&self.items[slice])
        } else {
            Err(StoreError::Uninit(slice))
        }
    }

    /// Returns a mutable slice if it is set.
    #[inline]
    pub fn try_get_slice_mut(&mut self, slice: Slice) -> Result<&mut [T]> {
        if slice.to_range().is_subset(&self.set) {
            Ok(&mut self.items[slice])
        } else {
            Err(StoreError::Uninit(slice))
        }
    }
}

impl<T: Default> Store<T> {
    /// Allocates uninitialized memory with the given length.
    #[inline]
    pub fn alloc(&mut self, len: usize) -> Slice {
        let ptr = Ptr::new(self.items.len());
        let slice = Slice::new_unchecked(ptr, len);

        self.items
            .resize_with(self.items.len() + len, Default::default);

        slice
    }
}

impl<T: Copy> Store<T> {
    /// Allocates memory with the given data.
    #[inline]
    pub fn alloc_with(&mut self, data: &[T]) -> Slice {
        let ptr = Ptr::new(self.items.len());
        let slice = Slice::new_unchecked(ptr, data.len());

        self.items.extend_from_slice(data);
        self.set |= slice.to_range();

        slice
    }

    /// Attempts to set data, returning an error if it is already set.
    #[inline]
    pub fn try_set(&mut self, slice: Slice, data: &[T]) -> Result<()> {
        let range = slice.to_range();
        if range.is_subset(&self.set) {
            return Err(StoreError::AlreadySet(slice));
        } else if range.end > self.items.len() {
            return Err(StoreError::InvalidSlice(slice));
        }

        self.set |= range.clone();
        self.items[range].copy_from_slice(data);

        Ok(())
    }
}

/// A linear bit store which ensures uninitialized data is not accessed.
#[derive(Debug, Clone, Default)]
pub struct BitStore {
    bits: BitVec,
    set: RangeSet,
}

impl BitStore {
    /// Creates a new store.
    #[inline]
    pub fn new() -> Self {
        Self {
            bits: BitVec::new(),
            set: RangeSet::default(),
        }
    }

    /// Creates a new store with the given capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bits: BitVec::with_capacity(capacity),
            set: RangeSet::default(),
        }
    }

    /// Returns whether the given range is set.
    #[inline]
    pub fn is_set(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.set)
    }

    /// Returns the ranges which are set.
    #[inline]
    pub fn set_ranges(&self) -> &RangeSet {
        &self.set
    }

    /// Returns a slice if it is set.
    #[inline]
    pub fn try_get(&self, slice: Slice) -> Result<&BitSlice> {
        if slice.to_range().is_subset(&self.set) {
            Ok(&self.bits[slice])
        } else {
            Err(StoreError::Uninit(slice))
        }
    }

    /// Returns a mutable slice if it is set.
    #[inline]
    pub fn try_get_mut(&mut self, slice: Slice) -> Result<&mut BitSlice> {
        if slice.to_range().is_subset(&self.set) {
            Ok(&mut self.bits[slice])
        } else {
            Err(StoreError::Uninit(slice))
        }
    }

    /// Allocates uninitialized memory with the given length.
    #[inline]
    pub fn alloc(&mut self, len: usize) -> Slice {
        let ptr = Ptr::new(self.bits.len());
        let slice = Slice::new_unchecked(ptr, len);

        self.bits.resize(self.bits.len() + len, false);

        slice
    }

    /// Allocates memory with the given data.
    #[inline]
    pub fn alloc_with(&mut self, data: &BitSlice) -> Slice {
        let ptr = Ptr::new(self.bits.len());
        let slice = Slice::new_unchecked(ptr, data.len());

        self.bits.extend_from_bitslice(data);
        self.set |= slice.to_range();

        slice
    }

    /// Attempts to set data, returning an error if it is already set.
    #[inline]
    pub fn try_set(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        let range = slice.to_range();
        if range.is_subset(&self.set) {
            return Err(StoreError::AlreadySet(slice));
        } else if range.end > self.bits.len() {
            return Err(StoreError::InvalidSlice(slice));
        }

        self.set |= &range;
        self.bits[range].copy_from_bitslice(data);

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid slice: {}", .0)]
    InvalidSlice(Slice),
    #[error("data is not initialized: {}", .0)]
    Uninit(Slice),
    #[error("data is already set: {}", .0)]
    AlreadySet(Slice),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store() {
        let mut store = Store::new();
        let range = store.alloc(10);

        assert!(!store.is_set(range.clone()));

        let data = vec![1; 10];
        store.try_set(range.clone(), &data).unwrap();

        assert!(store.is_set(range.clone()));
        assert_eq!(store.try_get(range.clone()).unwrap(), &data[..]);

        let range2 = store.alloc(10);
        assert!(!store.is_set(range2.clone()));
    }

    #[test]
    fn test_bit_store() {
        let mut store = BitStore::new();
        let range = store.alloc(10);

        assert!(!store.is_set(range.clone()));

        let data = BitVec::from_iter([
            false, true, false, true, false, true, false, true, false, true,
        ]);
        store.try_set(range.clone(), &data).unwrap();

        assert!(store.is_set(range.clone()));
        assert_eq!(store.try_get(range.clone()).unwrap(), &data);

        let range2 = store.alloc(10);
        assert!(!store.is_set(range2.clone()));
    }
}
