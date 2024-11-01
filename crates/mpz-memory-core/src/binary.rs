use itybity::{FromBitIterator, IntoBitIterator, IntoBits};
use mpz_core::bitvec::BitVec;

use crate::{ClearValue, FromRaw, MemoryType, Ptr, Repr, Slice, StaticSize, ToRaw};

pub struct Binary;

impl MemoryType for Binary {
    type Raw = BitVec;
}

macro_rules! impl_uint {
    ($ty:ty, $ident:ident, $size:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $ident(Ptr);

        impl Repr<Binary> for $ident {
            type Clear = $ty;
        }

        impl StaticSize<Binary> for $ty {
            const SIZE: usize = $size;
        }

        impl<const N: usize> StaticSize<Binary> for [$ty; N] {
            const SIZE: usize = $size * N;
        }

        impl StaticSize<Binary> for $ident {
            const SIZE: usize = $size;
        }

        impl<const N: usize> StaticSize<Binary> for [$ident; N] {
            const SIZE: usize = $size * N;
        }

        impl FromRaw<Binary> for $ident {
            fn from_raw(slice: Slice) -> Self {
                Self(slice.ptr)
            }
        }

        impl ToRaw for $ident {
            fn to_raw(&self) -> Slice {
                Slice::new_unchecked(self.0, Self::SIZE)
            }
        }

        impl ClearValue<Binary> for $ty {
            fn into_clear(self) -> BitVec {
                BitVec::from_iter(self.into_iter_lsb0())
            }

            fn from_clear(value: BitVec) -> Self {
                debug_assert_eq!(value.len(), $size);
                <$ty>::from_lsb0_iter(value.iter().by_vals())
            }
        }

        impl<const N: usize> ClearValue<Binary> for [$ty; N] {
            fn into_clear(self) -> BitVec {
                BitVec::from_iter(self.into_iter_lsb0())
            }

            fn from_clear(value: BitVec) -> Self {
                debug_assert_eq!(value.len(), $size * N);
                Self::from_lsb0_iter(value.iter().by_vals())
            }
        }

        impl ClearValue<Binary> for Vec<$ty> {
            fn into_clear(self) -> BitVec {
                BitVec::from_iter(self.into_iter_lsb0())
            }

            fn from_clear(value: BitVec) -> Self {
                Self::from_lsb0_iter(value.iter().by_vals())
            }
        }
    };
}

impl_uint!(u8, U8, 8);
impl_uint!(u16, U16, 16);
impl_uint!(u32, U32, 32);
impl_uint!(u64, U64, 64);
impl_uint!(u128, U128, 128);

macro_rules! impl_clear_value_for_tuples {
    // Macro for generating implementations for tuples with element identifiers and indices.
    ($($name:ident : $index:tt),+) => {
        impl<$($name),+> ClearValue<Binary> for ($($name,)+)
        where
            $($name: ClearValue<Binary> + StaticSize<Binary>,)+
        {
            fn into_clear(self) -> BitVec {
                let mut value = BitVec::new();
                // Extend the BitVec with each tuple element's clear value using the indices
                $(
                    value.extend_from_bitslice(&self.$index.into_clear());
                )+
                value
            }

            #[allow(unused_assignments)]
            fn from_clear(value: BitVec) -> Self {
                let mut offset = 0;
                (
                    $(
                        {
                            let size = $name::SIZE;
                            let elem = $name::from_clear(value[offset..offset + size].to_bitvec());
                            offset += size;
                            elem
                        },
                    )+
                )
            }
        }
    };
}

impl_clear_value_for_tuples!(T0: 0, T1: 1);
impl_clear_value_for_tuples!(T0: 0, T1: 1, T2: 2);
impl_clear_value_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3);
impl_clear_value_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3, T4: 4);
impl_clear_value_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5);
impl_clear_value_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6);
impl_clear_value_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6, T7: 7);
