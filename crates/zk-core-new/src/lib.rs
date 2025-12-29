use core::array::from_fn;
use std::ops::{BitXor, Not};

use itybity::{GetBit, Lsb0};
use mpz_memory_core::correlated::{Delta, Key, Mac};
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};

mod prover;
mod verifier;

/// A value that is either clear or encoded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ValueState<C, E> {
    Clear(C),
    Encoded(E),
}

pub use prover::Prover;
pub use verifier::Verifier;

pub type U8Key = U8<Key>;
pub type U8Mac = U8<Mac>;
pub type I32Key = I32<Key>;
pub type I32Mac = I32<Mac>;
pub type I64Key = I64<Key>;
pub type I64Mac = I64<Mac>;

/// A triple (a, b, c) where c = a AND b, used for consistency check.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Triple<T>(pub [T; 3]);

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct U8<T>([T; 8]);

impl Distribution<U8<Key>> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> U8<Key> {
        U8(from_fn(|_| {
            let mut key: Key = self.sample(rng);
            key.set_pointer(false);
            key
        }))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct I32<T>([T; 32]);

impl<T> I32<T>
where
    T: Copy,
{
    #[inline]
    pub(crate) fn to_le_bytes(self) -> [U8<T>; 4] {
        from_fn(|i| U8(from_fn(|j| self.0[(i / 8) + j])))
    }
}

impl Distribution<I32<Key>> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> I32<Key> {
        I32(from_fn(|_| {
            let mut key: Key = self.sample(rng);
            key.set_pointer(false);
            key
        }))
    }
}

impl I32<Key> {
    #[inline]
    pub(crate) fn from_bool(bit: Key, delta: &Delta) -> Self {
        let mut out = Self(from_fn(|_| Key::public(false, delta)));
        out.0[0] = bit;
        out
    }

    #[inline]
    pub(crate) fn from_le_bytes(bytes: [ValueState<u8, U8<Key>>; 4], delta: &Delta) -> Self {
        Self(from_fn(|i| match &bytes[i / 8] {
            ValueState::Clear(v) => Key::public(GetBit::<Lsb0>::get_bit(v, i % 8), delta),
            ValueState::Encoded(v) => v.0[i % 8],
        }))
    }

    #[inline]
    pub fn auth(&self, v: i32, delta: &Delta) -> I32<Mac> {
        let v = v as u32;
        I32(from_fn(|i| {
            let bit = GetBit::<Lsb0>::get_bit(&v, i);
            self.0[i].auth(bit, delta)
        }))
    }

    #[inline]
    pub fn not(mut self, delta: &Delta) -> Self {
        self.0.iter_mut().for_each(|key| key.adjust(true, delta));
        self
    }
}

impl I32<Mac> {
    #[inline]
    pub(crate) fn from_bool(bit: Mac) -> Self {
        let mut out = Self(from_fn(|_| Mac::PUBLIC[0]));
        out.0[0] = bit;
        out
    }

    #[inline]
    pub(crate) fn from_le_bytes(bytes: [ValueState<u8, U8<Mac>>; 4]) -> Self {
        Self(from_fn(|i| match &bytes[i / 8] {
            ValueState::Clear(v) => Mac::PUBLIC[GetBit::<Lsb0>::get_bit(v, i % 8) as usize],
            ValueState::Encoded(v) => v.0[i % 8],
        }))
    }
}

impl Not for I32<Mac> {
    type Output = Self;

    #[inline]
    fn not(mut self) -> Self::Output {
        self.0.iter_mut().for_each(|mac| mac.invert_pointer());
        self
    }
}

impl Not for &I32<Mac> {
    type Output = I32<Mac>;

    #[inline]
    fn not(self) -> Self::Output {
        !(*self)
    }
}

impl BitXor for I32<Mac> {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(from_fn(|i| self.0[i] ^ rhs.0[i]))
    }
}

impl BitXor for &I32<Mac> {
    type Output = I32<Mac>;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        I32(from_fn(|i| self.0[i] ^ rhs.0[i]))
    }
}

impl BitXor for I32<Key> {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

impl BitXor for &I32<Key> {
    type Output = I32<Key>;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        I32(from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct I64<T>([T; 64]);

impl<T> I64<T>
where
    T: Copy,
{
    #[inline]
    pub(crate) fn to_le_bytes(self) -> [U8<T>; 8] {
        from_fn(|i| U8(from_fn(|j| self.0[(i / 8) + j])))
    }
}

impl Distribution<I64<Key>> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> I64<Key> {
        I64(from_fn(|_| {
            let mut key: Key = self.sample(rng);
            key.set_pointer(false);
            key
        }))
    }
}

impl I64<Key> {
    #[inline]
    pub(crate) fn from_le_bytes(bytes: [ValueState<u8, U8<Key>>; 8], delta: &Delta) -> Self {
        Self(from_fn(|i| match &bytes[i / 8] {
            ValueState::Clear(v) => Key::public(GetBit::<Lsb0>::get_bit(v, i % 8), delta),
            ValueState::Encoded(v) => v.0[i % 8],
        }))
    }
}

impl I64<Mac> {
    #[inline]
    pub(crate) fn from_le_bytes(bytes: [ValueState<u8, U8<Mac>>; 8]) -> Self {
        Self(from_fn(|i| match &bytes[i / 8] {
            ValueState::Clear(v) => Mac::PUBLIC[GetBit::<Lsb0>::get_bit(v, i % 8) as usize],
            ValueState::Encoded(v) => v.0[i % 8],
        }))
    }
}

impl<T> Default for I64<T>
where
    T: Default,
{
    fn default() -> Self {
        Self(from_fn(|_| Default::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_memory_core::correlated::{Delta, Key, Mac};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    use crate::I32;

    fn gen_masks(rng: &mut StdRng, delta: &Delta, len: usize) -> (Vec<bool>, Vec<Key>, Vec<Mac>) {
        let mask_bits: Vec<bool> = (0..len).map(|_| rng.random()).collect();
        let mask_keys: Vec<Key> = (0..len).map(|_| rng.random()).collect();
        let mask_macs = mask_keys
            .iter()
            .zip(&mask_bits)
            .map(|(key, bit)| key.auth(*bit, delta))
            .collect();

        (mask_bits, mask_keys, mask_macs)
    }

    fn assert_triples(delta: &Delta, keys: &[Triple<Key>], macs: &[Triple<Mac>]) {
        for (key, mac) in keys.iter().zip(macs) {
            let [a, b, c] = mac.0.map(|mac| mac.pointer());
            let [key_a, key_b, key_c] = key.0;
            let [mac_a, mac_b, mac_c] = mac.0;

            assert_eq!(a & b, c);
            assert_eq!(key_a.auth(a, delta), mac_a);
            assert_eq!(key_b.auth(b, delta), mac_b);
            assert_eq!(key_c.auth(c, delta), mac_c);
        }
    }

    #[test]
    fn test_wrapping_add() {
        const MASK_LEN: usize = 31;
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let (mut mask_bits, mut mask_keys, mut mask_macs) = gen_masks(&mut rng, &delta, MASK_LEN);

        let key_a: I32<Key> = rng.random();
        let key_b: I32<Key> = rng.random();
        let a: i32 = rng.random();
        let b: i32 = rng.random();
        let mac_a = key_a.auth(a, &delta);
        let mac_b = key_b.auth(b, &delta);

        let out = a.wrapping_add(b);
        let mut mac_out = I32::default();
        let mut mac_triples = vec![Triple::default(); MASK_LEN];
        prover::arithmetic::wrapping_add(
            &mac_a.0,
            &mac_b.0,
            &mut mac_out.0,
            &mut mask_bits,
            &mut mask_macs,
            &mut mac_triples,
        );

        let mut key_out = I32::default();
        let mut key_triples = vec![Triple::default(); MASK_LEN];
        verifier::arithmetic::wrapping_add(
            &key_a.0,
            &key_b.0,
            &mut key_out.0,
            &delta,
            &mask_bits,
            &mut mask_keys,
            &mut key_triples,
        );

        assert_eq!(key_out.auth(out, &delta), mac_out);
        assert_triples(&delta, &key_triples, &mac_triples);
    }
}
