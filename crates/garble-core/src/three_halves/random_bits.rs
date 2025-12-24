//! Random Bit Source for Garbling
//!
//! This module provides an efficient source of random bits for garbling
//! operations. Random bits are pre-generated in bulk and consumed sequentially
//! to avoid repeated RNG calls during circuit processing.

use rand::Rng;

/// Pre-generated random bits for efficient consumption during garbling.
///
/// Random bits are packed into u64 words and extracted one at a time.
/// This is more efficient than calling the RNG for each individual bit.
pub(super) struct RandomBitSource {
    /// Pre-generated random words
    data: Vec<u64>,
    /// Current bit index
    bit_idx: usize,
}

impl RandomBitSource {
    /// Create a new source with pre-generated random bits.
    ///
    /// # Arguments
    /// * `num_bits` - Total number of random bits needed
    /// * `rng` - Random number generator to use for generation
    pub(super) fn new<R: Rng>(num_bits: usize, rng: &mut R) -> Self {
        let num_u64s = (num_bits + 63) / 64;
        let data: Vec<u64> = (0..num_u64s).map(|_| rng.random()).collect();
        Self { data, bit_idx: 0 }
    }

    /// Get the next random bit.
    #[inline]
    pub(super) fn next_bit(&mut self) -> bool {
        let word_idx = self.bit_idx / 64;
        let bit_pos = self.bit_idx % 64;
        self.bit_idx += 1;
        (self.data[word_idx] >> bit_pos) & 1 == 1
    }

    /// Get the next two random bits.
    #[inline]
    pub(super) fn next_two_bits(&mut self) -> [bool; 2] {
        [self.next_bit(), self.next_bit()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_random_bits_match_rng() {
        let seed = 42;

        let mut rng1 = ChaCha12Rng::seed_from_u64(seed);
        let mut source = RandomBitSource::new(32, &mut rng1);

        let mut rng2 = ChaCha12Rng::seed_from_u64(seed);
        let expected: u32 = rng2.random();

        // Extract 32 bits in mixed order: 1, 2, 1, 2, 1, 2, ... (10 calls = 15 bits)
        // Then 1, 2, 1, 2, 1, 2, 1, 1, 1 (9 calls = 17 bits) = 32 total
        let mut actual: u32 = 0;
        let mut bit_idx = 0;

        // Mixed extraction pattern
        for _ in 0..5 {
            actual |= (source.next_bit() as u32) << bit_idx;
            bit_idx += 1;
            let two = source.next_two_bits();
            actual |= (two[0] as u32) << bit_idx;
            actual |= (two[1] as u32) << (bit_idx + 1);
            bit_idx += 2;
        }
        // Remaining 17 bits
        for _ in 0..5 {
            let two = source.next_two_bits();
            actual |= (two[0] as u32) << bit_idx;
            actual |= (two[1] as u32) << (bit_idx + 1);
            bit_idx += 2;
        }
        for _ in 0..7 {
            actual |= (source.next_bit() as u32) << bit_idx;
            bit_idx += 1;
        }

        assert_eq!(actual, expected);
    }
}
