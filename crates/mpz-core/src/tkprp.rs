//! Implement the two-key PRG as G(k) = PRF_seed0(k)\xor k || PRF_seed1(k)\xor k
//! Refer to (<https://www.usenix.org/system/files/conference/nsdi17/nsdi17-wang-frank.pdf>, Page 8)

use crate::{aes::AesEncryptor, Block};

/// Struct of two-key prp.
/// This implementation is adapted from EMP toolkit.
pub struct TwoKeyPrp([AesEncryptor; 2]);

impl TwoKeyPrp {
    /// New an instance of TwoKeyPrp
    #[inline(always)]
    pub fn new(seeds: [Block; 2]) -> Self {
        Self([AesEncryptor::new(seeds[0]), AesEncryptor::new(seeds[1])])
    }

    /// Expands inputs to the destination slice.
    ///
    /// Outputs are written to the destination slice in the same order as the
    /// inputs.
    ///
    /// # Panics
    ///
    /// Panics if the destination slice is not twice the length of the input
    /// slice.
    ///
    /// # Arguments
    ///
    /// * `inputs` - The input blocks to expand with the two-key PRP.
    /// * `dest` - The destination slice to write the expanded blocks.
    pub fn expand(&self, inputs: &[Block], dest: &mut [Block]) {
        assert_eq!(
            dest.len(),
            inputs.len() * 2,
            "dest should have twice the length of inputs"
        );

        inputs
            .iter()
            .zip(dest.chunks_exact_mut(2))
            .for_each(|(input, dest)| {
                dest[1] = *input;
                dest[0] = *input;
                self.0[1].encrypt_block_inplace(&mut dest[1]);
                self.0[0].encrypt_block_inplace(&mut dest[0]);
                dest[1] ^= *input;
                dest[0] ^= *input;
            });
    }
}
