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

    /// expand 1 to 2
    #[inline(always)]
    pub(crate) fn expand_1to2(&self, children: &mut [Block], parent: Block) {
        children[0] = parent;
        children[1] = parent;
        AesEncryptor::para_encrypt::<2, 1>(&self.0, children);
        children[0] ^= parent;
        children[1] ^= parent;
    }

    /// expand 2 to 4
    //     p[0]            p[1]
    // c[0]    c[1]    c[2]    c[3]
    // t[0]    t[2]    t[1]    t[3]
    #[inline(always)]
    pub(crate) fn expand_2to4(&self, children: &mut [Block], parent: &[Block]) {
        let mut tmp = [Block::ZERO; 4];
        children[3] = parent[1];
        children[2] = parent[1];
        children[1] = parent[0];
        children[0] = parent[0];

        tmp[3] = parent[1];
        tmp[1] = parent[1];
        tmp[2] = parent[0];
        tmp[0] = parent[0];

        AesEncryptor::para_encrypt::<2, 2>(&self.0, &mut tmp);

        children[3] ^= tmp[3];
        children[2] ^= tmp[1];
        children[1] ^= tmp[2];
        children[0] ^= tmp[0];
    }

    /// expand 4 to 8
    //     p[0]            p[1]            p[2]            p[3]
    // c[0]    c[1]    c[2]    c[3]    c[4]    c[5]    c[6]    c[7]
    // t[0]    t[4]    t[1]    t[5]    t[2]    t[6]    t[3]    t[7]
    #[inline(always)]
    pub(crate) fn expand_4to8(&self, children: &mut [Block], parent: &[Block]) {
        let mut tmp = [Block::ZERO; 8];
        children[7] = parent[3];
        children[6] = parent[3];
        children[5] = parent[2];
        children[4] = parent[2];
        children[3] = parent[1];
        children[2] = parent[1];
        children[1] = parent[0];
        children[0] = parent[0];

        tmp[7] = parent[3];
        tmp[3] = parent[3];
        tmp[6] = parent[2];
        tmp[2] = parent[2];
        tmp[5] = parent[1];
        tmp[1] = parent[1];
        tmp[4] = parent[0];
        tmp[0] = parent[0];

        AesEncryptor::para_encrypt::<2, 4>(&self.0, &mut tmp);

        children[7] ^= tmp[7];
        children[6] ^= tmp[3];
        children[5] ^= tmp[6];
        children[4] ^= tmp[2];
        children[3] ^= tmp[5];
        children[2] ^= tmp[1];
        children[1] ^= tmp[4];
        children[0] ^= tmp[0];
    }
}
