//! This crate provides types for working with finite fields.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub mod gf2_128;
pub mod p256;

use std::{
    error::Error,
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

use hybrid_array::{Array, ArraySize};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use thiserror::Error;
use typenum::Unsigned;

/// A trait for finite fields.
pub trait Field:
    Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Copy
    + Clone
    + Debug
    + 'static
    + Send
    + Sync
    + UniformRand
    + PartialOrd
    + Ord
    + PartialEq
    + Eq
    + FromBitIterator
    + GetBit<Lsb0>
    + GetBit<Msb0>
    + BitLength
    + Unpin
    + TryFrom<Array<u8, Self::ByteSize>, Error = FieldError>
{
    /// The number of bits of a field element.
    const BIT_SIZE: usize = <Self::BitSize as Unsigned>::USIZE;

    /// The number of bytes of a field element.
    const BYTE_SIZE: usize = <Self::ByteSize as Unsigned>::USIZE;

    /// The number of bits of a field element as a type number.
    type BitSize: ArraySize;

    /// The number of bytes of a field element as a type number.
    type ByteSize: ArraySize;

    /// Return the additive identity element.
    fn zero() -> Self;

    /// Return the multiplicative identity element.
    fn one() -> Self;

    /// Return a field element from a power of two.
    fn two_pow(rhs: u32) -> Self;

    /// Return the multiplicative inverse, returning `None` if the element is
    /// zero.
    fn inverse(self) -> Option<Self>;

    /// Return field element as little-endian bytes.
    fn to_le_bytes(&self) -> Vec<u8>;

    /// Return field element as big-endian bytes.
    fn to_be_bytes(&self) -> Vec<u8>;
}

/// Error type for finite fields.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct FieldError(Box<dyn Error + Send + Sync + 'static>);

/// A trait for sampling random elements of the field.
///
/// This is helpful, because we do not need to import other traits since this is
/// a supertrait of field (which is not possible with `Standard` and
/// `Distribution`).
pub trait UniformRand: Sized {
    /// Return a random field element.
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self;
}

impl<T> UniformRand for T
where
    Standard: Distribution<T>,
{
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        rng.sample(Standard)
    }
}

/// Iteratively multiplies some field element with another field element.
///
/// This function multiplies the last element in `powers` with some other field
/// element `factor` and appends the result to `powers`. This process is
/// repeated `count` times.
///
/// * `powers` - The vector to which the new higher powers get pushed.
/// * `factor` - The field element with which the last element of the vector is
///   multiplied.
/// * `count` - How many products are computed.
pub fn compute_product_repeated<T: Field>(powers: &mut Vec<T>, factor: T, count: usize) {
    for _ in 0..count {
        let last_power = *powers
            .last()
            .expect("Vector is empty. Cannot compute higher powers");
        powers.push(factor * last_power);
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_product_repeated, Field};
    use itybity::{GetBit, Lsb0};
    use mpz_core::{prg::Prg, Block};
    use rand::SeedableRng;

    pub(crate) fn test_field_basic<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);
        let a = T::rand(&mut rng);

        let zero = T::zero();
        let one = T::one();

        assert_eq!(a + zero, a);
        assert_eq!(a * zero, zero);
        assert_eq!(a * one, a);
        assert_eq!(a * a.inverse().unwrap(), one);
        assert_eq!(one.inverse().unwrap(), one);
        assert_eq!(a + -a, zero);
    }

    pub(crate) fn test_field_compute_product_repeated<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);
        let a = T::rand(&mut rng);

        let mut powers = vec![a];
        let factor = a * a;

        compute_product_repeated(&mut powers, factor, 2);

        assert_eq!(powers[0], a);
        assert_eq!(powers[1], powers[0] * factor);
        assert_eq!(powers[2], powers[1] * factor);
    }

    pub(crate) fn test_field_bit_ops<T: Field>() {
        let mut a = vec![false; T::BIT_SIZE];
        let mut b = vec![false; T::BIT_SIZE];

        a[0] = true;
        b[T::BIT_SIZE - 1] = true;

        let a = T::from_lsb0_iter(a);
        let b = T::from_lsb0_iter(b);

        assert_eq!(a, T::one());
        assert!(GetBit::<Lsb0>::get_bit(&a, 0));

        assert_eq!(b, T::two_pow(T::BIT_SIZE as u32 - 1));
        assert!(GetBit::<Lsb0>::get_bit(&b, T::BIT_SIZE - 1));
    }
}
