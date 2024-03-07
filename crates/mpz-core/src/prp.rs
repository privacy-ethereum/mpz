//! An implementation of Pseudo Random Permutation (PRP) based on AES.

use crate::{aes::AesEncryptor, Block};

/// Pseudo Random Permutation (PRP) based on AES.
pub struct Prp(AesEncryptor);

impl Prp {
    /// Creates a new instance of Prp.
    #[inline(always)]
    pub fn new(seed: Block) -> Self {
        Prp(AesEncryptor::new(seed))
    }

    /// Permute one block.
    #[inline(always)]
    pub fn permute_block(&self, blk: Block) -> Block {
        self.0.encrypt_block(blk)
    }

    /// Permute many blocks.
    #[inline(always)]
    pub fn permute_many_blocks<const N: usize>(&self, blks: &mut [Block; N]) {
        self.0.encrypt_many_blocks(blks)
    }

    /// Permute block slice.
    #[inline(always)]
    pub fn permute_block_inplace(&self, blks: &mut [Block]) {
        self.0.encrypt_blocks(blks);
    }
}
