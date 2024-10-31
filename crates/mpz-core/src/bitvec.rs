//! Bit vectors.

/// Bit vector.
<<<<<<< HEAD
pub type BitVec = bitvec::vec::BitVec<u32, bitvec::order::Lsb0>;
/// Bit slice.
pub type BitSlice = bitvec::slice::BitSlice<u32, bitvec::order::Lsb0>;
=======
pub type BitVec<T = u32> = bitvec::vec::BitVec<T, bitvec::order::Lsb0>;
/// Bit slice.
pub type BitSlice<T = u32> = bitvec::slice::BitSlice<T, bitvec::order::Lsb0>;
>>>>>>> b81b562 (feat: lazy ot (#186))
