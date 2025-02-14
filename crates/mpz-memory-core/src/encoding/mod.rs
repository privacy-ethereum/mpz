use itybity::{FromBitIterator, IntoBitIterator, IntoBits};
use mpz_core::{bitvec::BitVec, Block};

use crate::{ClearValue, MemoryType, StaticSize};

mod key;
mod mac;

pub use key::KeyEncoding;
pub use mac::MacEncoding;

pub struct Encoding;

impl MemoryType for Encoding {
    type Raw = BitVec;
}

impl StaticSize<Encoding> for Block {
    const SIZE: usize = 128;
}

impl<const N: usize> StaticSize<Encoding> for [Block; N] {
    const SIZE: usize = 128 * N;
}

impl ClearValue<Encoding> for Block {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), Self::SIZE);
        Self::from_lsb0_iter(value.iter().by_vals())
    }
}

impl<const N: usize> ClearValue<Encoding> for [Block; N] {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), Self::SIZE * N);
        Self::from_lsb0_iter(value.iter().by_vals())
    }
}

impl ClearValue<Encoding> for Vec<Block> {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        Self::from_lsb0_iter(value.iter().by_vals())
    }
}
