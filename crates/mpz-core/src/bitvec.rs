//! Bit vectors.

/// Bit vector.
pub type BitVec<T = u32> = bitvec::vec::BitVec<T, bitvec::order::Lsb0>;
/// Bit slice.
pub type BitSlice<T = u32> = bitvec::slice::BitSlice<T, bitvec::order::Lsb0>;
