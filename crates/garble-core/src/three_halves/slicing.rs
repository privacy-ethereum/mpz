//! Wire Label Slicing for Three Halves Garbling
//!
//! This module implements the "slicing" technique from the Three Halves paper.
//! Wire labels are split into left and right halves (κ/2 bits each), allowing
//! the evaluator to compute each half using potentially different linear
//! combinations.
//!
//! # Paper Reference
//!
//! Section 3.1 (Page 8):
//! > "We slice a wire label W into two halves W_L and W_R, each of length κ/2."
//!
//! Section 5 (Page 11):
//! > "The slicing technique means that 'half' of each wire label (i.e., κ/2
//! > bits)
//! > can be computed from a different linear combination."
//!
//! # Layout
//!
//! A 128-bit Block is split as follows:
//! ```text
//! Block (128 bits):  [byte0, byte1, ..., byte7, byte8, ..., byte15]
//!                    [======= left =======][======= right ========]
//!                         (64 bits)              (64 bits)
//! ```
//!
//! The left half occupies bytes 0-7, the right half occupies bytes 8-15.
//! This matches the little-endian layout used throughout mpz.

use mpz_core::Block;

/// A wire label split into left and right halves.
///
/// Each half is κ/2 = 64 bits, stored as `[u8; 8]`.
///
/// # Paper Reference
///
/// The paper uses notation like `A_L` and `A_R` for left and right halves
/// of a wire label `A`. This struct represents that split form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlicedLabel {
    /// Left half of the wire label (κ/2 bits)
    ///
    /// In evaluation equations, this appears in even rows (0, 2, 4, 6).
    pub left: [u8; 8],

    /// Right half of the wire label (κ/2 bits)
    ///
    /// In evaluation equations, this appears in odd rows (1, 3, 5, 7).
    pub right: [u8; 8],
}

impl SlicedLabel {
    /// Create a new SlicedLabel from left and right halves.
    #[inline]
    pub const fn new(left: [u8; 8], right: [u8; 8]) -> Self {
        Self { left, right }
    }

    /// Create a zero-valued SlicedLabel.
    pub const ZERO: Self = Self {
        left: [0u8; 8],
        right: [0u8; 8],
    };

    /// Split a 128-bit Block into left and right halves.
    ///
    /// # Layout
    ///
    /// ```text
    /// Block bytes:  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    ///               [======= left ========][========== right ===========]
    /// ```
    #[inline]
    pub fn from_block(block: Block) -> Self {
        let [left, right]: [[u8; 8]; 2] = bytemuck::cast(block);
        Self { left, right }
    }

    /// Recombine left and right halves into a 128-bit Block.
    #[inline]
    pub fn to_block(&self) -> Block {
        bytemuck::cast([self.left, self.right])
    }
}

impl From<Block> for SlicedLabel {
    #[inline]
    fn from(block: Block) -> Self {
        Self::from_block(block)
    }
}

impl From<SlicedLabel> for Block {
    #[inline]
    fn from(sliced: SlicedLabel) -> Self {
        sliced.to_block()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    /// Round-trip conversion
    ///
    /// Splitting and recombining should give back the original block.
    #[test]
    fn test_roundtrip() {
        let mut rng = ChaCha12Rng::seed_from_u64(42);

        // Test with random block
        let block = Block::random(&mut rng);
        let sliced = SlicedLabel::from_block(block);
        let recovered = sliced.to_block();
        assert_eq!(block, recovered, "Round-trip failed");

        // Test with zero block
        let zero_sliced = SlicedLabel::from_block(Block::ZERO);
        assert_eq!(zero_sliced.left, [0u8; 8]);
        assert_eq!(zero_sliced.right, [0u8; 8]);
        assert_eq!(zero_sliced.to_block(), Block::ZERO);

        // Test with all-ones block
        let ones_sliced = SlicedLabel::from_block(Block::ONES);
        assert_eq!(ones_sliced.left, [0xffu8; 8]);
        assert_eq!(ones_sliced.right, [0xffu8; 8]);
        assert_eq!(ones_sliced.to_block(), Block::ONES);
    }

    /// From/Into trait implementations
    #[test]
    fn test_from_into_traits() {
        let mut rng = ChaCha12Rng::seed_from_u64(999);
        let block = Block::random(&mut rng);

        // Test From<Block> for SlicedLabel
        let sliced: SlicedLabel = block.into();
        assert_eq!(sliced, SlicedLabel::from_block(block));

        // Test From<SlicedLabel> for Block
        let recovered: Block = sliced.into();
        assert_eq!(recovered, block);
    }
}
