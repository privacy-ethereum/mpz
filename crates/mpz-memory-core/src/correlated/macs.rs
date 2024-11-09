use std::ops::Add;

use blake3::{Hash, Hasher};
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use serde::{Deserialize, Serialize};

use crate::{
    correlated::{MAC_ONE, MAC_ZERO},
    store::{Store, StoreError},
    RangeSet, Slice,
};

type Result<T> = core::result::Result<T, MacStoreError>;

/// MAC.
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Mac(Block);

impl Mac {
    /// Public MACs.
    pub const PUBLIC: [Mac; 2] = [Mac(MAC_ZERO), Mac(MAC_ONE)];

    /// Creates a new MAC.
    #[inline]
    pub(crate) fn new(block: Block) -> Self {
        Self(block)
    }

    /// Returns the pointer bit.
    #[inline]
    pub fn pointer(&self) -> bool {
        self.0.lsb()
    }

    /// Sets the pointer bit.
    #[inline]
    pub fn set_pointer(&mut self, bit: bool) {
        self.0.set_lsb(bit);
    }

    /// Returns the MAC encoded as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the MAC block.
    #[inline]
    pub fn as_block(&self) -> &Block {
        &self.0
    }

    /// Converts a slice of MACs to a slice of blocks.
    #[inline]
    pub fn as_blocks(slice: &[Self]) -> &[Block] {
        // Safety:
        // Mac is a newtype of block.
        unsafe { &*(slice as *const [Self] as *const [Block]) }
    }

    /// Converts a `Vec` of blocks to a `Vec` of MACs.
    #[inline]
    pub fn from_blocks(blocks: Vec<Block>) -> Vec<Self> {
        // Safety:
        // Mac is a newtype of block.
        unsafe { std::mem::transmute(blocks) }
    }

    /// Returns MACs for public data.
    #[inline]
    pub fn public(data: impl IntoIterator<Item = bool>) -> impl Iterator<Item = Self> {
        data.into_iter().map(|bit| Self::PUBLIC[bit as usize])
    }
}

impl From<Mac> for Block {
    #[inline]
    fn from(mac: Mac) -> Block {
        mac.0
    }
}

impl From<Block> for Mac {
    #[inline]
    fn from(block: Block) -> Mac {
        Mac(block)
    }
}

impl Add<Mac> for Mac {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Mac) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Add<&Mac> for Mac {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Mac) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Add<Mac> for &Mac {
    type Output = Mac;

    #[inline]
    fn add(self, rhs: Mac) -> Mac {
        Mac(self.0 ^ rhs.0)
    }
}

impl Add<&Mac> for &Mac {
    type Output = Mac;

    #[inline]
    fn add(self, rhs: &Mac) -> Mac {
        Mac(self.0 ^ rhs.0)
    }
}

/// A linear store which manages correlated MACs.
#[derive(Debug, Clone, Default)]
pub struct MacStore {
    macs: Store<Mac>,
}

impl MacStore {
    /// Creates a new MAC store.
    #[inline]
    pub fn new() -> Self {
        Self {
            macs: Store::default(),
        }
    }

    /// Returns whether all the MACs are set.
    #[inline]
    pub fn is_set(&self, slice: Slice) -> bool {
        self.macs.is_set(slice)
    }

    /// Returns the ranges of set MACs.
    #[inline]
    pub fn set_ranges(&self) -> &RangeSet {
        self.macs.set_ranges()
    }

    /// Allocates uninitialized memory.
    #[inline]
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.macs.alloc(len)
    }

    /// Allocates memory with the given MACs.
    #[inline]
    pub fn alloc_with(&mut self, macs: &[Mac]) -> Slice {
        self.macs.alloc_with(macs)
    }

    /// Returns MACs if they are set.
    #[inline]
    pub fn try_get(&self, slice: Slice) -> Result<&[Mac]> {
        self.macs.try_get(slice).map_err(From::from)
    }

    /// Sets MACs, returning an error if they are already set.
    #[inline]
    pub fn try_set(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.macs.try_set(slice, macs).map_err(From::from)
    }

    /// Sets MACs for public data, returning an error if they are already set.
    #[inline]
    pub fn try_set_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        let macs = Mac::public(data.iter().map(|bit| *bit)).collect::<Vec<_>>();
        self.macs.try_set(slice, &macs).map_err(From::from)
    }

    /// Returns the pointer bits of the MACs if they are set.
    pub fn try_get_bits(&self, slice: Slice) -> Result<impl Iterator<Item = bool> + '_> {
        self.macs
            .try_get(slice)
            .map(|macs| macs.iter().map(|mac| mac.pointer()))
            .map_err(From::from)
    }

    /// Adjusts the MACs for the given range.
    ///
    /// # Panics
    ///
    /// Panics if the data is not the same length as the range.
    ///
    /// # Arguments
    ///
    /// * `slice` - Range to adjust.
    /// * `data` - Plaintext data.
    pub fn adjust(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        assert_eq!(
            slice.size,
            data.len(),
            "data is not the same length as the range"
        );

        self.macs
            .try_get_slice_mut(slice)?
            .iter_mut()
            .zip(data)
            .for_each(|(mac, bit)| {
                mac.set_pointer(*bit);
            });

        Ok(())
    }

    /// Proves MACs.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Ranges to prove.
    pub fn prove(&self, ranges: &RangeSet) -> Result<(BitVec, Hash)> {
        let mut bits = BitVec::with_capacity(ranges.len());
        let mut hasher = Hasher::new();
        for range in ranges.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.macs.try_get(slice)?.iter().for_each(|mac| {
                bits.push(mac.pointer());
                hasher.update(&mac.as_bytes());
            });
        }

        Ok((bits, hasher.finalize()))
    }
}

/// Error for [`MacStore`].
#[derive(Debug, thiserror::Error)]
pub enum MacStoreError {
    #[error("invalid slice: {}", .0)]
    InvalidSlice(Slice),
    #[error("MACs are not initialized: {}", .0)]
    Uninit(Slice),
    #[error("MACs are already set: {}", .0)]
    AlreadySet(Slice),
    #[error("MACs are already assigned: {}", .0)]
    AlreadyAssigned(Slice),
    #[error("MAC verification error")]
    Verify,
}

impl From<StoreError> for MacStoreError {
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
        let mut store = MacStore::new();

        let macs = vec![Mac::PUBLIC[0], Mac::PUBLIC[1]];

        let slice = store.alloc_with(&macs);
        let data = BitVec::<u32>::from_iter([true, false]);

        store.adjust(slice, &data).unwrap();

        let bits = store
            .try_get(slice)
            .unwrap()
            .iter()
            .map(|mac| mac.pointer())
            .collect::<Vec<_>>();

        assert_eq!(bits, vec![true, false]);
    }
}
