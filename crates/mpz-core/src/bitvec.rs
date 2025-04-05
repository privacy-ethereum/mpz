//! Bit vectors.

/// Bit vector.
pub type BitVec = bitvec::vec::BitVec<u32, bitvec::order::Lsb0>;
/// Bit slice.
pub type BitSlice<T = u32> = bitvec::slice::BitSlice<T, bitvec::order::Lsb0>;
