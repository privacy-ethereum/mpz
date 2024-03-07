//! This module implements the prime field of P256.

use std::ops::{Add, Mul, Neg};

use ark_ff::{BigInt, BigInteger, Field as ArkField, FpConfig, MontBackend, One, Zero};
use ark_secp256r1::{fq::Fq, FqConfig};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use num_bigint::ToBigUint;
use rand::{distributions::Standard, prelude::Distribution};
use serde::{Deserialize, Serialize};

use super::Field;

/// A type for holding field elements of P256.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "[u8; 32]")]
#[serde(try_from = "[u8; 32]")]
pub struct P256(pub(crate) Fq);

opaque_debug::implement!(P256);

impl P256 {
    /// Creates a new field element, returning `None` if the value is not a valid element.
    pub fn new(value: impl ToBigUint) -> Option<Self> {
        value.to_biguint().map(|input| P256(Fq::from(input)))
    }
}

impl From<P256> for [u8; 32] {
    fn from(value: P256) -> Self {
        let mut bytes = [0u8; 32];

        value
            .0
            .serialize_with_mode(&mut bytes[..], Compress::No)
            .expect("field element should be 32 bytes");

        bytes
    }
}

impl TryFrom<[u8; 32]> for P256 {
    type Error = ark_serialize::SerializationError;

    /// Converts little-endian bytes into a P256 field element.
    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        Fq::deserialize_with_mode(&value[..], Compress::No, Validate::Yes).map(P256)
    }
}

impl Distribution<P256> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> P256 {
        P256(self.sample(rng))
    }
}

impl Add for P256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Mul for P256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Neg for P256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Field for P256 {
    const BIT_SIZE: u32 = 256;

    fn zero() -> Self {
        P256(<Fq as Zero>::zero())
    }

    fn one() -> Self {
        P256(<Fq as One>::one())
    }

    fn two_pow(rhs: u32) -> Self {
        let mut out = <Fq as One>::one();
        for _ in 0..rhs {
            MontBackend::<FqConfig, 4>::double_in_place(&mut out);
        }

        P256(out)
    }

    fn inverse(self) -> Self {
        P256(ArkField::inverse(&self.0).expect("Unable to invert field element"))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        BigInt::to_bytes_le(&MontBackend::<FqConfig, 4>::into_bigint(self.0))
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        BigInt::to_bytes_be(&MontBackend::<FqConfig, 4>::into_bigint(self.0))
    }
}

impl BitLength for P256 {
    const BITS: usize = 256;
}

impl GetBit<Lsb0> for P256 {
    fn get_bit(&self, index: usize) -> bool {
        MontBackend::<FqConfig, 4>::into_bigint(self.0).get_bit(index)
    }
}

impl GetBit<Msb0> for P256 {
    fn get_bit(&self, index: usize) -> bool {
        MontBackend::<FqConfig, 4>::into_bigint(self.0).get_bit(256 - index)
    }
}

impl FromBitIterator for P256 {
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        P256(BigInt::from_bits_le(&iter.into_iter().collect::<Vec<bool>>()).into())
    }

    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        P256(BigInt::from_bits_be(&iter.into_iter().collect::<Vec<bool>>()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_core::{prg::Prg, Block};
    use rand::{Rng, SeedableRng};

    use crate::tests::{test_field_basic, test_field_bit_ops, test_field_compute_product_repeated};

    #[test]
    fn test_p256_basic() {
        test_field_basic::<P256>();
        assert_eq!(P256::new(0).unwrap(), P256::zero());
        assert_eq!(P256::new(1).unwrap(), P256::one());
    }

    #[test]
    fn test_p256_compute_product_repeated() {
        test_field_compute_product_repeated::<P256>();
    }

    #[test]
    fn test_p256_bit_ops() {
        test_field_bit_ops::<P256>();
    }

    #[test]
    fn test_p256_serialize() {
        let mut rng = Prg::from_seed(Block::ZERO);

        for _ in 0..32 {
            let a = P256(rng.gen());
            let bytes: [u8; 32] = a.into();
            let b = P256::try_from(bytes).unwrap();

            assert_eq!(a, b);
        }
    }
}
