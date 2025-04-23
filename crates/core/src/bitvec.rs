//! Bit vectors.

/// Bit vector.
pub type BitVec = bitvec::vec::BitVec<u32, bitvec::order::Lsb0>;
/// Bit slice.
pub type BitSlice = bitvec::slice::BitSlice<u32, bitvec::order::Lsb0>;
