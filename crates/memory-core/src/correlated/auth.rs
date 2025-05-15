use mpz_core::bitvec::{BitSlice, BitVec};

use crate::{
    correlated::{Delta, Key, Mac, MacStore, KeyStore, MacStoreError, KeyStoreError},
    store::{BitStore, StoreError},
    RangeSet, Slice,
};

type Result<T> = core::result::Result<T, AuthBitStoreError>;

/// A store for authenticated bits, consisting of a bool value, a MAC, and a Key.
#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone)]
pub struct AuthBitStore {
    bits: BitStore,
    macs: MacStore,
    keys: KeyStore,
}

impl AuthBitStore {
    /// Creates a new authenticated bit store.
    #[inline]
    pub fn new(delta: Delta) -> Self {
        Self {
            bits: BitStore::new(),
            macs: MacStore::new(),
            keys: KeyStore::new(delta),
        }
    }

    /// Returns the delta of the authenticated bit store.
    #[inline]
    pub fn delta(&self) -> &Delta {
        self.keys.delta()
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
        self.bits.alloc(len);
        self.macs.alloc(len);
        self.keys.alloc(len)
    }

    /// Allocates bits.
    #[inline]
    pub fn alloc_bits(&mut self, bits: &BitSlice) -> Slice {
        self.bits.alloc_with(bits)
    }

    /// Allocates bits.
    #[inline]
    pub fn alloc_macs(&mut self, macs: &[Mac]) -> Slice {
        self.macs.alloc_with(macs)
    }

    /// Allocates keys.
    #[inline]
    pub fn alloc_keys(&mut self, keys: &[Key]) -> Slice {
        self.keys.alloc_with(keys)
    }

    /// Returns bits if they are set.
    #[inline]
    pub fn try_get_bits(&self, slice: Slice) -> Result<&BitSlice> {
        self.bits.try_get(slice).map_err(From::from)
    }

    /// Returns bits if they are set.
    #[inline]
    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.macs.try_get(slice).map_err(From::from)
    }

    /// Returns keys if they are set.
    #[inline]
    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.keys.try_get(slice).map_err(From::from)
    }

    /// Sets authenticated bits, returning an error if they are already set.
    #[inline]
    pub fn try_set_bits(&mut self, slice: Slice, bits: &BitSlice) -> Result<()> {
        self.bits.try_set(slice, bits).map_err(From::from)
    }

    /// Sets authenticated bits, returning an error if they are already set.
    #[inline]
    pub fn try_set_macs(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.macs.try_set(slice, macs).map_err(From::from)
    }

    /// Sets authenticated bits, returning an error if they are already set.
    #[inline]
    pub fn try_set_keys(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.keys.try_set(slice, keys).map_err(From::from)
    }

    /// Proves MACs.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Ranges to prove.
    pub fn prove_share(&self, ranges: &RangeSet) -> Result<(BitVec, Vec<Mac>)> {
        let mut bits = BitVec::with_capacity(ranges.len());
        let mut macs = Vec::with_capacity(ranges.len());
        for range in ranges.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let slice_bits = self.bits.try_get(slice)?;
            let slice_macs = self.macs.try_get(slice)?;    
            for (bit, mac) in slice_bits.iter().zip(slice_macs) {
                bits.push(*bit);
                macs.push(*mac);
            }
        }

        Ok((bits, macs))
    }

    pub fn check_share(&mut self, ranges: &RangeSet, bits: &BitVec, macs: &[Mac]) -> Result<()> {
        let mut expected_macs = Vec::with_capacity(ranges.len());
        for range in ranges.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            expected_macs.extend(self.keys.authenticate(slice, bits)?);
        }

        if expected_macs != macs {
            return Err(AuthBitStoreError::Verify);
        }
        
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
    #[error("authenticated bits are already assigned: {}", .0)]
    AlreadyAssigned(Slice),
    #[error("authenticated bits verification failed")]
    Verify,
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

impl From<MacStoreError> for AuthBitStoreError {
    fn from(err: MacStoreError) -> Self {
        match err {
            MacStoreError::InvalidSlice(slice) => Self::InvalidSlice(slice),
            MacStoreError::Uninit(slice) => Self::Uninit(slice),
            MacStoreError::AlreadySet(slice) => Self::AlreadySet(slice),
            MacStoreError::AlreadyAssigned(slice) => Self::AlreadyAssigned(slice),
            MacStoreError::Verify => Self::Verify,
        }
    }
}

impl From<KeyStoreError> for AuthBitStoreError {
    fn from(err: KeyStoreError) -> Self {
        match err {
            KeyStoreError::InvalidSlice(slice) => Self::InvalidSlice(slice),
            KeyStoreError::Uninit(slice) => Self::Uninit(slice),
            KeyStoreError::AlreadySet(slice) => Self::AlreadySet(slice),
            KeyStoreError::AlreadyAssigned(slice) => Self::AlreadyAssigned(slice),
            KeyStoreError::Verify => Self::Verify,
        }
    }
}

