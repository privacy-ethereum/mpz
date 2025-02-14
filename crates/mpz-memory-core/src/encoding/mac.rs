use mpz_core::Block;

use crate::{encoding::Encoding, FromRaw, Ptr, Repr, Slice, StaticSize, ToRaw};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacEncoding(Ptr);

impl Repr<Encoding> for MacEncoding {
    type Clear = Block;
}

impl<const N: usize> StaticSize<Encoding> for [MacEncoding; N] {
    const SIZE: usize = 128 * N;
}

impl StaticSize<Encoding> for MacEncoding {
    const SIZE: usize = 128;
}

impl FromRaw<Encoding> for MacEncoding {
    fn from_raw(slice: Slice) -> Self {
        Self(slice.ptr)
    }
}

impl ToRaw for MacEncoding {
    fn to_raw(&self) -> Slice {
        Slice::new_unchecked(self.0, Self::SIZE)
    }
}
