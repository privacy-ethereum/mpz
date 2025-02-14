use mpz_core::Block;

use crate::{encoding::Encoding, FromRaw, Ptr, Repr, Slice, StaticSize, ToRaw};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEncoding(Ptr);

impl Repr<Encoding> for KeyEncoding {
    type Clear = Block;
}

impl<const N: usize> StaticSize<Encoding> for [KeyEncoding; N] {
    const SIZE: usize = 128 * N;
}

impl StaticSize<Encoding> for KeyEncoding {
    const SIZE: usize = 128;
}

impl FromRaw<Encoding> for KeyEncoding {
    fn from_raw(slice: Slice) -> Self {
        Self(slice.ptr)
    }
}

impl ToRaw for KeyEncoding {
    fn to_raw(&self) -> Slice {
        Slice::new_unchecked(self.0, Self::SIZE)
    }
}
