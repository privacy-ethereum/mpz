//! This crate provides types for working with finite fields.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

pub mod gf2;
pub mod gf2_128;
pub mod gf2_64;
pub mod p256;

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "pclmulqdq"),
    all(target_arch = "wasm32", target_feature = "simd128"),
)))]
mod bmul;

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod bmul_simd;

use std::{
    error::Error,
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

use hybrid_array::{Array, ArraySize};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::{Rng, distr::StandardUniform, prelude::Distribution};
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

    /// Compute the inner product `Σ aᵢ · bᵢ` of two slices of field elements.
    ///
    /// The default implementation is a straight fold; concrete types may
    /// override this with an accelerated variant (e.g. accumulating
    /// carry-less products without reducing, then reducing once at the end).
    ///
    /// # Panics
    ///
    /// Panics if the two slices have different lengths.
    fn inner_product(a: &[Self], b: &[Self]) -> Self {
        assert_eq!(a.len(), b.len(), "inner_product: slice length mismatch");
        a.iter()
            .zip(b.iter())
            .fold(Self::zero(), |acc, (x, y)| acc + *x * *y)
    }
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
    StandardUniform: Distribution<T>,
{
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        rng.sample(StandardUniform)
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
    use super::{Field, compute_product_repeated};
    use itybity::{GetBit, Lsb0, Msb0};
    use mpz_core::{Block, prg::Prg};
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

    pub(crate) fn test_field_axioms_random<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);
        let zero = T::zero();
        let one = T::one();

        for _ in 0..1000 {
            let a = T::rand(&mut rng);
            let b = T::rand(&mut rng);
            let c = T::rand(&mut rng);

            assert_eq!(a * b, b * a, "commutativity");
            assert_eq!((a * b) * c, a * (b * c), "associativity");
            assert_eq!(a * (b + c), a * b + a * c, "distributivity");
            assert_eq!(a + -a, zero, "additive inverse");
            #[allow(clippy::eq_op)]
            {
                assert_eq!(a - a, zero, "self-subtraction");
            }
            if a != zero {
                assert_eq!(a * a.inverse().unwrap(), one, "multiplicative inverse");
            }
        }
    }

    pub(crate) fn test_field_inner_product<T: Field>() {
        let mut rng = Prg::from_seed(Block::ZERO);

        // Empty → zero.
        assert_eq!(T::inner_product(&[], &[]), T::zero());

        // Length 1 → a · b.
        let a0 = T::rand(&mut rng);
        let b0 = T::rand(&mut rng);
        assert_eq!(T::inner_product(&[a0], &[b0]), a0 * b0);

        // Length 1024 — stresses the x86 accumulator across many folds.
        for &len in &[17usize, 1024] {
            let a: Vec<T> = (0..len).map(|_| T::rand(&mut rng)).collect();
            let b: Vec<T> = (0..len).map(|_| T::rand(&mut rng)).collect();

            let expected = a
                .iter()
                .zip(b.iter())
                .fold(T::zero(), |acc, (x, y)| acc + *x * *y);

            assert_eq!(T::inner_product(&a, &b), expected, "len={len}");
        }
    }

    pub(crate) fn test_field_bit_ops_lsb0<T: Field>() {
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

    pub(crate) fn test_field_bit_ops_msb0<T: Field>() {
        let mut a = vec![false; T::BIT_SIZE];
        let mut b = vec![false; T::BIT_SIZE];

        a[T::BIT_SIZE - 1] = true;
        b[0] = true;

        let a = T::from_msb0_iter(a);
        let b = T::from_msb0_iter(b);

        assert_eq!(a, T::one());
        assert!(GetBit::<Msb0>::get_bit(&a, T::BIT_SIZE - 1));

        assert_eq!(b, T::two_pow(T::BIT_SIZE as u32 - 1));
        assert!(GetBit::<Msb0>::get_bit(&b, 0));
    }
}
