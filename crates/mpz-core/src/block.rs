//! A block of 128 bits and its operations.

use bytemuck::{Pod, Zeroable};
use clmul::Clmul;
use core::ops::{BitAnd, BitAndAssign, BitXor, BitXorAssign};
use generic_array::{typenum::consts::U16, GenericArray};
use itybity::{BitIterable, BitLength, GetBit, Lsb0, Msb0};
use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng};
use serde::{Deserialize, Serialize};

/// A block of 128 bits
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Serialize, Deserialize, Pod, Zeroable)]
pub struct Block([u8; 16]);

impl Block {
    /// The length of a block in bytes
    pub const LEN: usize = 16;
    /// A zero block
    pub const ZERO: Self = Self([0; 16]);
    /// A one block
    pub const ONE: Self = Self([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// A block with all bits set to 1
    pub const ONES: Self = Self([0xff; 16]);
    /// A length 2 array of zero and one blocks
    pub const SELECT_MASK: [Self; 2] = [Self::ZERO, Self::ONES];

    /// Create a new block
    #[inline]
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the byte representation of the block
    #[inline]
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Generate a random block using the provided RNG
    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }

    /// Generate a random array of blocks using the provided RNG
    #[inline]
    pub fn random_array<const N: usize, R: Rng + CryptoRng>(rng: &mut R) -> [Self; N] {
        std::array::from_fn(|_| rng.gen::<[u8; 16]>().into())
    }

    /// Generate a random vector of blocks using the provided RNG
    #[inline]
    pub fn random_vec<R: Rng + CryptoRng + ?Sized>(rng: &mut R, n: usize) -> Vec<Self> {
        (0..n).map(|_| rng.gen::<[u8; 16]>().into()).collect()
    }

    /// Carry-less multiplication of two blocks, without the reduction step.
    #[inline]
    pub fn clmul(self, other: Self) -> (Self, Self) {
        let (a, b) = Clmul::new(&self.0).clmul(Clmul::new(&other.0));
        (Self::new(a.into()), Self::new(b.into()))
    }

    #[inline]
    /// Reduces the polynomial represented in bits modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1.
    /// `x` and `y` are resp. upper and lower bits of the polynomial.
    pub fn reduce_gcm(x: Self, y: Self) -> Self {
        let r = Clmul::reduce_gcm(Clmul::new(&x.0), Clmul::new(&y.0));
        Self::new(r.into())
    }

    /// The multiplication of two Galois field elements.
    #[inline]
    pub fn gfmul(self, x: Self) -> Self {
        let (a, b) = self.clmul(x);
        Block::reduce_gcm(a, b)
    }

    /// Compute the inner product of two block vectors, without reducing the polynomial.
    #[inline]
    pub fn inn_prdt_no_red(a: &[Block], b: &[Block]) -> (Block, Block) {
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b.iter())
            .fold((Block::ZERO, Block::ZERO), |acc, (x, y)| {
                let t = x.clmul(*y);
                (t.0 ^ acc.0, t.1 ^ acc.1)
            })
    }

    /// Compute the inner product of two block vectors.
    #[inline]
    pub fn inn_prdt_red(a: &[Block], b: &[Block]) -> Block {
        let (x, y) = Block::inn_prdt_no_red(a, b);
        Block::reduce_gcm(x, y)
    }

    /// Reverses the bits of the block
    #[inline]
    pub fn reverse_bits(self) -> Self {
        Self(u128::from_le_bytes(self.0).reverse_bits().to_le_bytes())
    }

    /// Sets the least significant bit of the block
    #[inline]
    pub fn set_lsb(&mut self) {
        self.0[0] |= 1;
    }

    /// Returns the least significant bit of the block
    #[inline]
    pub fn lsb(&self) -> usize {
        ((self.0[0] & 1) == 1) as usize
    }

    /// Let `x0` and `x1` be the lower and higher halves of `x`, respectively.
    /// This function compute ``sigma( x = x0 || x1 ) = x1 || (x0 xor x1)``.
    #[inline(always)]
    pub fn sigma(a: Self) -> Self {
        let mut x: [u64; 2] = bytemuck::cast(a);
        x[0] ^= x[1];
        bytemuck::cast([x[1], x[0]])
    }

    /// Converts a block to a [`GenericArray<u8, U16>`](cipher::generic_array::GenericArray)
    /// from the [`generic-array`](https://docs.rs/generic-array/latest/generic_array/) crate.
    #[allow(dead_code)]
    pub(crate) fn as_generic_array(&self) -> &GenericArray<u8, U16> {
        (&self.0).into()
    }

    /// Converts a mutable block to a mutable [`GenericArray<u8, U16>`](cipher::generic_array::GenericArray)
    /// from the [`generic-array`](https://docs.rs/generic-array/latest/generic_array/) crate.
    pub(crate) fn as_generic_array_mut(&mut self) -> &mut GenericArray<u8, U16> {
        (&mut self.0).into()
    }

    /// Converts a slice of blocks to a slice of [`GenericArray<u8, U16>`](cipher::generic_array::GenericArray)
    /// from the [`generic-array`](https://docs.rs/generic-array/latest/generic_array/) crate.
    #[allow(dead_code)]
    pub(crate) fn as_generic_array_slice(slice: &[Self]) -> &[GenericArray<u8, U16>] {
        // # Safety
        // This is always safe because `Block` and `GenericArray<u8, U16>` have the same memory layout.
        // See https://github.com/fizyk20/generic-array/blob/37dc6aefc3ed5c423ad7402d4febf06a3e78a223/src/lib.rs#L838-L845
        // TODO: Use methods provided by `generic-array` once 1.0 is released.
        unsafe { std::mem::transmute(slice) }
    }

    /// Converts a mutable slice of blocks to a mutable slice of [`GenericArray<u8, U16>`](cipher::generic_array::GenericArray)
    /// from the [`generic-array`](https://docs.rs/generic-array/latest/generic_array/) crate.
    pub(crate) fn as_generic_array_mut_slice(slice: &mut [Self]) -> &mut [GenericArray<u8, U16>] {
        // # Safety
        // This is always safe because `Block` and `GenericArray<u8, U16>` have the same memory layout.
        // See https://github.com/fizyk20/generic-array/blob/37dc6aefc3ed5c423ad7402d4febf06a3e78a223/src/lib.rs#L847-L854
        // TODO: Use methods provided by `generic-array` once 1.0 is released.
        unsafe { std::mem::transmute(slice) }
    }
}

/// A trait for converting a type to blocks
pub trait BlockSerialize {
    /// The block representation of the type
    type Serialized: std::fmt::Debug + Clone + Copy + Send + Sync + 'static;

    /// Convert the type to blocks
    fn to_blocks(self) -> Self::Serialized;

    /// Convert the blocks to the type
    fn from_blocks(blocks: Self::Serialized) -> Self;
}

impl BitLength for Block {
    const BITS: usize = 128;
}

impl GetBit<Lsb0> for Block {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Lsb0>::get_bit(&self.0[index / 8], index % 8)
    }
}

impl GetBit<Msb0> for Block {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Msb0>::get_bit(&self.0[15 - (index / 8)], index % 8)
    }
}

impl BitIterable for Block {}

impl From<[u8; 16]> for Block {
    #[inline]
    fn from(bytes: [u8; 16]) -> Self {
        Block::new(bytes)
    }
}

impl<'a> From<&'a [u8; 16]> for &'a Block {
    fn from(bytes: &'a [u8; 16]) -> Self {
        bytemuck::cast_ref(bytes)
    }
}

impl<'a> TryFrom<&'a [u8]> for Block {
    type Error = <[u8; 16] as TryFrom<&'a [u8]>>::Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        <[u8; 16]>::try_from(value).map(Self::from)
    }
}

impl From<Block> for GenericArray<u8, U16> {
    #[inline]
    fn from(b: Block) -> Self {
        b.0.into()
    }
}

impl<'a> From<&'a Block> for &'a GenericArray<u8, U16> {
    #[inline]
    fn from(b: &'a Block) -> Self {
        (&b.0).into()
    }
}

impl From<GenericArray<u8, U16>> for Block {
    #[inline]
    fn from(b: GenericArray<u8, U16>) -> Self {
        Block::new(b.into())
    }
}

impl<'a> From<&'a GenericArray<u8, U16>> for &'a Block {
    #[inline]
    fn from(b: &'a GenericArray<u8, U16>) -> Self {
        let b: &'a [u8; 16] = b.as_ref();
        b.into()
    }
}

impl From<Block> for [u8; 16] {
    #[inline]
    fn from(b: Block) -> Self {
        b.0
    }
}

impl<'a> From<&'a Block> for &'a [u8; 16] {
    #[inline]
    fn from(b: &'a Block) -> Self {
        &b.0
    }
}

impl BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        Self(std::array::from_fn(|i| self.0[i] ^ other.0[i]))
    }
}

impl BitXorAssign for Block {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitAnd for Block {
    type Output = Self;

    #[inline]
    fn bitand(self, other: Self) -> Self::Output {
        Self(std::array::from_fn(|i| self.0[i] & other.0[i]))
    }
}

impl BitAndAssign for Block {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs
    }
}

impl Distribution<Block> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        Block::new(rng.gen())
    }
}

impl AsMut<[u8]> for Block {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use itybity::ToBits;

    use super::*;

    #[test]
    fn test_set_lsb() {
        let zero = [0; 16];
        let mut one = [0; 16];
        one[0] = 1;
        let mut three = [0; 16];
        three[0] = 3;

        let mut b = Block::new(zero);
        b.set_lsb();
        assert_eq!(Block::new(one), b);

        // no-op when the bit is already set
        let mut b = Block::new(three);
        b.set_lsb();
        assert_eq!(Block::new(three), b);
    }

    #[test]
    fn test_lsb() {
        let a = Block::new([0; 16]);
        assert_eq!(a.lsb(), 0);

        let mut one = [0; 16];
        one[0] = 1;

        let a = Block::new(one);
        assert_eq!(a.lsb(), 1);

        let mut two = [0; 16];
        two[0] = 2;

        let a = Block::new(two);
        assert_eq!(a.lsb(), 0);

        let mut three = [0; 16];
        three[0] = 3;

        let a = Block::new(three);
        assert_eq!(a.lsb(), 1);
    }

    #[test]
    fn test_reverse_bits() {
        let a = Block::new([42; 16]);

        let mut expected_bits = a.to_lsb0_vec();
        expected_bits.reverse();

        assert_eq!(a.reverse_bits().to_lsb0_vec(), expected_bits);
    }

    #[test]
    fn inn_prdt_test() {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha12Rng;
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        const SIZE: usize = 1000;
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut c = (Block::ZERO, Block::ZERO);
        let mut d = Block::ZERO;
        for i in 0..SIZE {
            let r: [u8; 16] = rng.gen();
            a.push(Block::from(r));
            let r: [u8; 16] = rng.gen();
            b.push(Block::from(r));

            let z = a[i].clmul(b[i]);
            c.0 ^= z.0;
            c.1 ^= z.1;

            let x = a[i].gfmul(b[i]);
            d ^= x;
        }

        assert_eq!(c, Block::inn_prdt_no_red(&a, &b));
        assert_eq!(d, Block::inn_prdt_red(&a, &b));
    }

    #[test]
    fn sigma_test() {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha12Rng;
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let mut x: [u8; 16] = rng.gen();
        let bx = Block::sigma(Block::from(x));
        let (xl, xr) = x.split_at_mut(8);

        for (x, y) in xl.iter_mut().zip(xr.iter_mut()) {
            *x ^= *y;
            std::mem::swap(x, y);
        }
        let expected_sigma = Block::from(x);
        assert_eq!(bx, expected_sigma);
    }
}
