//! This module implements the extension field GF(2^128).

use std::ops::{Add, Mul, Neg};

use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0};
use rand::{distributions::Standard, prelude::Distribution};
use serde::{Deserialize, Serialize};

use mpz_core::Block;

use super::Field;

/// A type for holding field elements of Gf(2^128).
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gf2_128(pub(crate) u128);

opaque_debug::implement!(Gf2_128);

impl Gf2_128 {
    /// Creates a new field element from a u128,
    /// mapping the integer to the corresponding polynomial.
    ///
    /// For example, 5u128 is mapped to the polynomial `1 + x^2`.
    pub fn new(input: u128) -> Self {
        Gf2_128(input)
    }

    /// Returns the field element as a u128.
    pub fn to_inner(self) -> u128 {
        self.0
    }
}

impl From<Gf2_128> for Block {
    fn from(value: Gf2_128) -> Self {
        Block::new(value.0.to_be_bytes())
    }
}

impl From<Block> for Gf2_128 {
    fn from(block: Block) -> Self {
        Gf2_128(u128::from_be_bytes(block.to_bytes()))
    }
}

impl Distribution<Gf2_128> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Gf2_128 {
        Gf2_128(self.sample(rng))
    }
}

impl Add for Gf2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2_128 {
    type Output = Self;

    /// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial.
    fn mul(self, rhs: Self) -> Self::Output {
        // See NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC.
        //
        // Note that the NIST specification uses a different representation of the polynomial, where the bits are
        // reversed. This "bit reflection" is discussed in Intel® Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode.
        //
        // The irreducible polynomial is the same, ie `x^128 + x^7 + x^2 + x + 1`.

        const R: u128 = 0x00000000000000000000000000000087;

        let mut x = self.0;
        let mut y = rhs.0;
        let mut z = 0u128;

        // https://en.wikipedia.org/wiki/Finite_field_arithmetic#C_programming_example
        //
        // TODO: Use RustCrypto polyval crate.
        while (x != 0) && (y != 0) {
            z ^= (y & 1) * x;
            x = (x << 1) ^ ((x >> 127) * R);
            y >>= 1;
        }

        Gf2_128(z)
    }
}

impl Neg for Gf2_128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Field for Gf2_128 {
    const BIT_SIZE: u32 = 128;

    fn zero() -> Self {
        Self::new(0)
    }

    fn one() -> Self {
        Self::new(1)
    }

    fn two_pow(rhs: u32) -> Self {
        Self(1 << rhs)
    }

    /// Galois field inversion of 128-bit block.
    fn inverse(self) -> Self {
        let mut a = self;
        let mut out = Self::one();
        for _ in 0..127 {
            a = a * a;
            out = out * a;
        }
        out
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

impl BitLength for Gf2_128 {
    const BITS: usize = 128;
}

impl GetBit<Lsb0> for Gf2_128 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Lsb0>::get_bit(&self.0, index)
    }
}

impl GetBit<Msb0> for Gf2_128 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Msb0>::get_bit(&self.0, index)
    }
}

impl FromBitIterator for Gf2_128 {
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Self(u128::from_lsb0_iter(iter))
    }

    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Self(u128::from_msb0_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use super::Gf2_128;
    use crate::{
        tests::{test_field_basic, test_field_bit_ops, test_field_compute_product_repeated},
        Field,
    };
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use mpz_core::{prg::Prg, Block};
    use rand::SeedableRng;

    #[test]
    fn test_gf2_128_basic() {
        test_field_basic::<Gf2_128>();
        assert_eq!(Gf2_128::new(0), Gf2_128::zero());
        assert_eq!(Gf2_128::new(1), Gf2_128::one());
    }

    #[test]
    fn test_gf2_128_compute_product_repeated() {
        test_field_compute_product_repeated::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_bit_ops() {
        test_field_bit_ops::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_mul() {
        // Naive multiplication is the same here.
        let a = Gf2_128::new(3);
        let b = Gf2_128::new(5);

        // Here we cannot calculate naively.
        let c = Gf2_128::new(3);
        let d = Gf2_128::new(7);

        // Test vector from Intel® Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode.
        let e = Gf2_128::new(0x7b5b54657374566563746f725d53475d);
        let f = Gf2_128::new(0x48692853686179295b477565726f6e5d);

        assert_eq!(a * b, b * a);
        assert_eq!(a * b, Gf2_128::new(15));
        assert_eq!(c * d, Gf2_128::new(9));
        assert_eq!(e * f, Gf2_128::new(0x40229a09a5ed12e7e4e10da323506d2));
    }

    #[test]
    // Test multiplication against RustCrypto.
    fn test_gf2_128_against_ghash_impl() {
        let mut rng = Prg::from_seed(Block::ZERO);

        let a = Block::random(&mut rng);
        let b = Block::random(&mut rng);

        let mut g = GHash::new(&a.to_bytes().into());
        g.update(&b.to_bytes().into());
        let expected = Block::from(g.finalize().into_bytes());

        // GHASH reverses the bits of the blocks before performing multiplication
        // then reverses the output.
        let a: Gf2_128 = a.reverse_bits().into();
        let b: Gf2_128 = b.reverse_bits().into();
        let output: Block = (a * b).into();
        let output = output.reverse_bits();

        assert_eq!(expected, output);
    }
}
