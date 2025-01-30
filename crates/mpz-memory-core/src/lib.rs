pub mod binary;
pub mod correlated;
mod decode;
pub mod store;
pub mod view;

pub use decode::{DecodeError, DecodeFuture, DecodeFutureTyped, DecodeOp};

use core::fmt;
use std::{
    marker::PhantomData,
    ops::{Index, IndexMut},
};

use mpz_core::bitvec::{BitSlice, BitVec};
use serde::{Deserialize, Serialize};

pub(crate) type RangeSet = utils::range::RangeSet<usize>;
pub(crate) type Range = std::ops::Range<usize>;

/// Virtual-machine memory.
pub trait Memory<T: MemoryType> {
    /// Memory error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Allocates a new slice of memory.
    fn alloc_raw(&mut self, size: usize) -> Result<Slice, Self::Error>;

    /// Assigns data to the slice.
    fn assign_raw(&mut self, slice: Slice, data: T::Raw) -> Result<(), Self::Error>;

    /// Commits the slice of memory.
    fn commit_raw(&mut self, slice: Slice) -> Result<(), Self::Error>;

    /// Gets the data from memory, returning `None` if the slice is not present.
    fn get_raw(&self, slice: Slice) -> Result<Option<T::Raw>, Self::Error>;

    /// Decodes data from memory.
    ///
    /// Returns a future which will resolve to the value when it is ready.
    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<T::Raw>, Self::Error>;
}

/// Extension trait for [`Memory`].
pub trait MemoryExt<T: MemoryType>: Memory<T> {
    /// Allocates a new value.
    fn alloc<R>(&mut self) -> Result<R, Self::Error>
    where
        R: Repr<T> + StaticSize<T>,
    {
        self.alloc_raw(R::SIZE).map(R::from_raw)
    }

    /// Allocates a vector.
    fn alloc_vec<R>(&mut self, len: usize) -> Result<Vector<R>, Self::Error>
    where
        R: Repr<T> + StaticSize<T>,
    {
        let size = R::SIZE * len;
        let slice = self.alloc_raw(size)?;

        Ok(Vector::from_raw(slice))
    }

    /// Assigns the value to memory.
    fn assign<R>(&mut self, value: R, clear: R::Clear) -> Result<(), Self::Error>
    where
        R: Repr<T>,
    {
        self.assign_raw(value.to_raw(), clear.into_clear())
    }

    /// Commits the value to memory.
    fn commit<R>(&mut self, value: R) -> Result<(), Self::Error>
    where
        R: Repr<T>,
    {
        self.commit_raw(value.to_raw())
    }

    /// Gets the value from memory, returning `None` if the value is not
    /// present.
    fn get<R>(&self, value: R) -> Result<Option<R::Clear>, Self::Error>
    where
        R: Repr<T>,
    {
        self.get_raw(value.to_raw())
            .map(|opt| opt.map(R::Clear::from_clear))
    }

    /// Decodes the value.
    ///
    /// Returns a future which will resolve to the value when it is ready.
    fn decode<R>(&mut self, value: R) -> Result<DecodeFutureTyped<T::Raw, R::Clear>, Self::Error>
    where
        R: Repr<T>,
    {
        self.decode_raw(value.to_raw())
            .map(|fut| DecodeFutureTyped::new(fut, <R::Clear as ClearValue<T>>::from_clear))
    }
}

impl<T: MemoryType, M> MemoryExt<T> for M where M: ?Sized + Memory<T> {}

/// Two-party memory view.
pub trait View<T: MemoryType> {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Marks the slice as public.
    fn mark_public_raw(&mut self, slice: Slice) -> Result<(), Self::Error>;

    /// Marks the slice as private.
    fn mark_private_raw(&mut self, slice: Slice) -> Result<(), Self::Error>;

    /// Marks the slice as blind.
    fn mark_blind_raw(&mut self, slice: Slice) -> Result<(), Self::Error>;
}

/// Extension trait for [`View`].
pub trait ViewExt<T: MemoryType>: View<T> {
    /// Marks the value as public.
    fn mark_public<R>(&mut self, value: R) -> Result<(), Self::Error>
    where
        R: ToRaw,
    {
        self.mark_public_raw(value.to_raw())
    }

    /// Marks the value as private.
    fn mark_private<R>(&mut self, value: R) -> Result<(), Self::Error>
    where
        R: ToRaw,
    {
        self.mark_private_raw(value.to_raw())
    }

    /// Marks the value as blind.
    fn mark_blind<R>(&mut self, value: R) -> Result<(), Self::Error>
    where
        R: ToRaw,
    {
        self.mark_blind_raw(value.to_raw())
    }
}

impl<M, T> ViewExt<T> for M
where
    M: ?Sized + View<T>,
    T: MemoryType,
{
}

/// Memory pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ptr(usize);

impl Ptr {
    pub(crate) fn new(ptr: usize) -> Self {
        Self(ptr)
    }

    /// Returns the pointer as a `usize`.
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for Ptr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

pub trait MemoryType {
    /// Raw memory type.
    type Raw;
}

pub trait ToRaw {
    /// Returns the underlying raw memory slice.
    fn to_raw(&self) -> Slice;
}

pub trait FromRaw<T: MemoryType> {
    /// Creates a new value from a raw memory slice.
    fn from_raw(slice: Slice) -> Self;
}

pub trait StaticSize<T> {
    /// Size of the type.
    const SIZE: usize;
}

pub trait Repr<T: MemoryType>: FromRaw<T> + ToRaw {
    type Clear: ClearValue<T>;
}

pub trait ClearValue<T: MemoryType> {
    /// Converts `self` into a raw clear value.
    fn into_clear(self) -> T::Raw;

    /// Converts a raw clear value into `Self`.
    fn from_clear(value: T::Raw) -> Self;
}

/// A slice of contiguous memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Slice {
    ptr: Ptr,
    size: usize,
}

impl Slice {
    /// Creates a new slice.
    ///
    /// Do not use this unless you know what you're doing. It will cause bugs
    /// and break security.
    #[inline]
    pub fn new_unchecked(ptr: Ptr, size: usize) -> Self {
        Self { ptr, size }
    }

    /// Creates a new slice from a range.
    ///
    /// Do not use this unless you know what you're doing. It will cause bugs
    /// and break security.
    #[inline]
    pub fn from_range_unchecked(range: Range) -> Self {
        Self {
            ptr: Ptr::new(range.start),
            size: range.len(),
        }
    }

    /// Returns a pointer to the start of slice.
    #[inline]
    pub fn ptr(&self) -> Ptr {
        self.ptr
    }

    /// Returns the length of the slice.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns the memory range of the slice.
    #[inline]
    pub fn to_range(&self) -> Range {
        self.ptr.as_usize()..self.ptr.as_usize() + self.size
    }

    /// Returns a `RangeSet` of the slices.
    pub fn to_rangeset(slices: impl IntoIterator<Item = Self>) -> RangeSet {
        RangeSet::from(
            slices
                .into_iter()
                .map(|slice| slice.to_range())
                .collect::<Vec<_>>(),
        )
    }
}

impl fmt::Display for Slice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Slice {{ ptr: {}, size: {} }}", self.ptr, self.size)
    }
}

impl From<Slice> for Range {
    fn from(slice: Slice) -> Self {
        slice.to_range()
    }
}

impl<T> Index<Slice> for [T] {
    type Output = [T];

    fn index(&self, index: Slice) -> &Self::Output {
        &self[index.to_range()]
    }
}

impl<T> Index<Slice> for Vec<T> {
    type Output = [T];

    fn index(&self, index: Slice) -> &Self::Output {
        &self[index.to_range()]
    }
}

impl<T> IndexMut<Slice> for [T] {
    fn index_mut(&mut self, index: Slice) -> &mut Self::Output {
        &mut self[index.to_range()]
    }
}

impl<T> IndexMut<Slice> for Vec<T> {
    fn index_mut(&mut self, index: Slice) -> &mut Self::Output {
        &mut self[index.to_range()]
    }
}

impl Index<Slice> for BitVec {
    type Output = BitSlice;

    fn index(&self, index: Slice) -> &Self::Output {
        &self[index.to_range()]
    }
}

impl IndexMut<Slice> for BitVec {
    fn index_mut(&mut self, index: Slice) -> &mut Self::Output {
        &mut self[index.to_range()]
    }
}

/// An array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Array<T, const N: usize> {
    slice: Slice,
    _pd: PhantomData<T>,
}

impl<T, const N: usize> Array<T, N> {
    pub(crate) const fn new(slice: Slice) -> Self {
        assert!(N > 0, "array size must be greater than 0");

        Self {
            slice,
            _pd: PhantomData,
        }
    }

    /// Returns a slice of the array, starting from `start`.
    ///
    /// Returns `None` if the slice is out of bounds.
    ///
    /// # Arguments
    ///
    /// * `start` - The start index of the slice.
    pub fn get<const M: usize>(&self, start: usize) -> Option<Array<T, M>> {
        let range = self.slice.to_range();

        let t_size = range.len() / N;
        let new_range = range.start + (start * t_size)..range.start + (start * t_size) + M;

        if new_range.is_empty() || new_range.end > range.end {
            return None;
        }

        Some(Array {
            slice: Slice::from_range_unchecked(new_range),
            _pd: PhantomData,
        })
    }
}

impl<T, const N: usize, R: MemoryType> FromRaw<R> for Array<T, N> {
    fn from_raw(slice: Slice) -> Self {
        Self::new(slice)
    }
}

impl<T, const N: usize> ToRaw for Array<T, N> {
    fn to_raw(&self) -> Slice {
        self.slice
    }
}

impl<T, R, const N: usize> StaticSize<R> for Array<T, N>
where
    T: StaticSize<R>,
{
    const SIZE: usize = N * T::SIZE;
}

impl<T, R, const N: usize> Repr<R> for Array<T, N>
where
    T: Repr<R>,
    R: MemoryType,
    [T::Clear; N]: ClearValue<R>,
{
    type Clear = [T::Clear; N];
}

/// A vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vector<T> {
    ptr: Ptr,
    item_size: usize,
    len: usize,
    _pd: PhantomData<T>,
}

impl<T> Vector<T> {
    /// Returns the length of the vector.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the vector is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a slice of the vector, or `None` if the range is out of bounds.
    pub fn get(&self, range: Range) -> Option<Vector<T>> {
        if range.end > self.len {
            return None;
        }

        let ptr = Ptr::new(self.ptr.as_usize() + range.start * self.item_size);

        Some(Vector {
            ptr,
            item_size: self.item_size,
            len: range.len(),
            _pd: PhantomData,
        })
    }

    /// Splits the collection into two at the given index.
    ///
    /// Returns a vector containing the elements in the range [at, len). After
    /// the call, the original vector will be left containing the elements [0,
    /// at).
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(at <= self.len, "index out of bounds");

        let ptr = Ptr::new(self.ptr.as_usize() + at * self.item_size);
        let len = self.len - at;

        self.len = at;

        Vector {
            ptr,
            item_size: self.item_size,
            len,
            _pd: PhantomData,
        }
    }

    /// Shortens the vector, keeping the first len elements and dropping the
    /// rest.
    ///
    /// If len is greater or equal to the vector’s current length, this has no
    /// effect.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }
}

impl<T, R: MemoryType> FromRaw<R> for Vector<T>
where
    T: StaticSize<R>,
{
    fn from_raw(slice: Slice) -> Self {
        debug_assert!(slice.size % T::SIZE == 0);

        Self {
            ptr: slice.ptr,
            item_size: T::SIZE,
            len: slice.size / T::SIZE,
            _pd: PhantomData,
        }
    }
}

impl<T> ToRaw for Vector<T> {
    fn to_raw(&self) -> Slice {
        Slice {
            ptr: self.ptr,
            size: self.item_size * self.len,
        }
    }
}

impl<T, R> Repr<R> for Vector<T>
where
    T: Repr<R> + StaticSize<R>,
    R: MemoryType,
    Vec<T::Clear>: ClearValue<R>,
{
    type Clear = Vec<T::Clear>;
}

#[derive(Debug, thiserror::Error)]
#[error("vector can not be converted to array: expected {expected} elements, got {actual}")]
pub struct TryFromVectorError {
    expected: usize,
    actual: usize,
}

impl<T, const N: usize> TryFrom<Vector<T>> for Array<T, N> {
    type Error = TryFromVectorError;

    fn try_from(value: Vector<T>) -> Result<Self, Self::Error> {
        if value.len != N {
            return Err(TryFromVectorError {
                expected: N,
                actual: value.len,
            });
        }

        Ok(Self::new(Slice {
            ptr: value.ptr,
            size: value.item_size * N,
        }))
    }
}

macro_rules! impl_from_raw_for_tuples {
    ($($name:ident),+) => {
        impl<$($name,)+ R> FromRaw<R> for ($($name,)+)
        where
            $($name: FromRaw<R> + StaticSize<R>,)+
            R: MemoryType,
        {
            #[allow(unused_assignments)]
            fn from_raw(slice: Slice) -> Self {
                let mut offset = 0;
                (
                    $(
                        {
                            let mut sub_slice = slice;
                            sub_slice.ptr.0 += offset;
                            sub_slice.size = $name::SIZE;
                            offset += $name::SIZE;
                            $name::from_raw(sub_slice)
                        },
                    )+
                )
            }
        }
    };
}

impl_from_raw_for_tuples!(T0, T1);
impl_from_raw_for_tuples!(T0, T1, T2);
impl_from_raw_for_tuples!(T0, T1, T2, T3);
impl_from_raw_for_tuples!(T0, T1, T2, T3, T4);
impl_from_raw_for_tuples!(T0, T1, T2, T3, T4, T5);
impl_from_raw_for_tuples!(T0, T1, T2, T3, T4, T5, T6);
impl_from_raw_for_tuples!(T0, T1, T2, T3, T4, T5, T6, T7);

macro_rules! impl_to_raw_for_tuples {
    ($($name:ident : $index:tt),+) => {
        impl<$($name,)+> ToRaw for ($($name,)+)
        where
            $($name: ToRaw,)+
        {
            #[allow(non_snake_case)]
            fn to_raw(&self) -> Slice {
                let mut slice = self.0.to_raw();
                $(
                    let next_slice = self.$index.to_raw();
                    slice.size += next_slice.size;
                )+
                slice
            }
        }
    };
}

impl_to_raw_for_tuples!(T0: 0, T1: 1);
impl_to_raw_for_tuples!(T0: 0, T1: 1, T2: 2);
impl_to_raw_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3);
impl_to_raw_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3, T4: 4);
impl_to_raw_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5);
impl_to_raw_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6);
impl_to_raw_for_tuples!(T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6, T7: 7);

macro_rules! impl_static_size_for_tuples {
    ($($ident:ident),+) => {
        impl<$($ident,)+ R> StaticSize<R> for ($($ident,)+)
        where
            $($ident: StaticSize<R>,)+
        {
            const SIZE: usize = 0 $(+ $ident::SIZE)+;
        }
    };
}

impl_static_size_for_tuples!(T0, T1);
impl_static_size_for_tuples!(T0, T1, T2);
impl_static_size_for_tuples!(T0, T1, T2, T3);
impl_static_size_for_tuples!(T0, T1, T2, T3, T4);
impl_static_size_for_tuples!(T0, T1, T2, T3, T4, T5);
impl_static_size_for_tuples!(T0, T1, T2, T3, T4, T5, T6);
impl_static_size_for_tuples!(T0, T1, T2, T3, T4, T5, T6, T7);

macro_rules! impl_repr_for_tuples {
    ($($ident:ident),+) => {
        impl<$($ident,)+ R> Repr<R> for ($($ident,)+)
        where
            $($ident: Repr<R> + StaticSize<R>,)+
            R: MemoryType,
            ($($ident::Clear,)+): ClearValue<R>,
        {
            type Clear = ($($ident::Clear,)+);
        }
    };
}

impl_repr_for_tuples!(T0, T1);
impl_repr_for_tuples!(T0, T1, T2);
impl_repr_for_tuples!(T0, T1, T2, T3);
impl_repr_for_tuples!(T0, T1, T2, T3, T4);
impl_repr_for_tuples!(T0, T1, T2, T3, T4, T5);
impl_repr_for_tuples!(T0, T1, T2, T3, T4, T5, T6);
impl_repr_for_tuples!(T0, T1, T2, T3, T4, T5, T6, T7);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::U8;

    #[test]
    fn test_vector_split_off() {
        let mut vec: Vector<U8> = Vector {
            ptr: Ptr::new(32),
            item_size: U8::SIZE,
            len: 5,
            _pd: PhantomData,
        };

        let new_vec = vec.split_off(2);

        assert_eq!(vec.len(), 2);
        assert_eq!(new_vec.len(), 3);

        assert_eq!(vec.ptr.as_usize(), 32);
        assert_eq!(new_vec.ptr.as_usize(), 32 + 2 * U8::SIZE);
    }
}
