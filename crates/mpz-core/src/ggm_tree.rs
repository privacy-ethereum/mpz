//! Implement GGM tree for OT.
//! Implementation of GGM based on the procedure explained in the write-up
//! (<https://eprint.iacr.org/2020/925.pdf>, Page 14)

use crate::{tkprp::TwoKeyPrp, Block};

/// Struct of GGM
pub struct GgmTree {
    tkprp: TwoKeyPrp,
    depth: usize,
}

impl GgmTree {
    ///New GgmTree instance.
    #[inline(always)]
    pub fn new(depth: usize) -> Self {
        let tkprp = TwoKeyPrp::new([Block::ZERO, Block::from(1u128.to_le_bytes())]);
        Self { tkprp, depth }
    }

    /// Create a GGM tree in-place.
    ///
    /// # Arguments
    ///
    /// * `seed` - a seed.
    /// * `tree` - the destination to write the GGM (binary tree) `tree`, with size `2^{depth}`.
    /// * `k0` - XORs of all the left-node values in each level, with size `depth`.
    /// * `k1`- XORs of all the right-node values in each level, with size `depth`.
    // This implementation is adapted from EMP Toolkit.
    pub fn gen(&self, seed: Block, tree: &mut [Block], k0: &mut [Block], k1: &mut [Block]) {
        assert_eq!(tree.len(), 1 << (self.depth));
        assert_eq!(k0.len(), self.depth);
        assert_eq!(k1.len(), self.depth);
        let mut buf = [Block::ZERO; 8];
        self.tkprp.expand_1to2(tree, seed);
        k0[0] = tree[0];
        k1[0] = tree[1];

        self.tkprp.expand_2to4(&mut buf, tree);
        k0[1] = buf[0] ^ buf[2];
        k1[1] = buf[1] ^ buf[3];
        tree[0..4].copy_from_slice(&buf[0..4]);

        for h in 2..self.depth {
            k0[h] = Block::ZERO;
            k1[h] = Block::ZERO;

            // How many nodes there are in this layer
            let sz = 1 << h;
            for i in (0..=sz - 4).rev().step_by(4) {
                self.tkprp.expand_4to8(&mut buf, &tree[i..]);
                k0[h] ^= buf[0];
                k0[h] ^= buf[2];
                k0[h] ^= buf[4];
                k0[h] ^= buf[6];
                k1[h] ^= buf[1];
                k1[h] ^= buf[3];
                k1[h] ^= buf[5];
                k1[h] ^= buf[7];

                tree[2 * i..2 * i + 8].copy_from_slice(&buf);
            }
        }
    }

    /// Reconstruct the GGM tree except the value in a given position.
    ///
    /// This reconstructs the GGM tree entirely except `tree[pos] == Block::ZERO`. The bit decomposition of `pos` is the complement of `alpha`. i.e., `pos[i] = 1 xor alpha[i]`.
    ///
    /// # Arguments
    ///
    /// * `k` - a slice of blocks with length `depth`, the values of k are chosen via OT from k0 and k1. For the i-th value, if alpha[i] == 1, k[i] = k1[i]; else k[i] = k0[i].
    /// * `alpha` - a slice of bits with length `depth`.
    /// * `tree` - the destination to write the GGM tree.
    pub fn reconstruct(&self, tree: &mut [Block], k: &[Block], alpha: &[bool]) {
        assert_eq!(tree.len(), 1 << (self.depth));
        assert_eq!(k.len(), self.depth);
        assert_eq!(alpha.len(), self.depth);

        let mut pos = 0;
        for i in 1..=self.depth {
            pos *= 2;
            tree[pos] = Block::ZERO;
            tree[pos + 1] = Block::ZERO;
            if !alpha[i - 1] {
                self.reconstruct_layer(i, false, pos, k[i - 1], tree);
                pos += 1;
            } else {
                self.reconstruct_layer(i, true, pos + 1, k[i - 1], tree);
            }
        }
    }

    // Handle each layer.
    fn reconstruct_layer(
        &self,
        depth: usize,
        left_or_right: bool,
        pos: usize,
        k: Block,
        tree: &mut [Block],
    ) {
        // How many nodes there are in this layer
        let sz = 1 << depth;

        let mut sum = Block::ZERO;
        let start = if left_or_right { 1 } else { 0 };

        for i in (start..sz).step_by(2) {
            sum ^= tree[i];
        }
        tree[pos] = sum ^ k;

        if depth == (self.depth) {
            return;
        }

        let mut buf = [Block::ZERO; 8];
        if sz == 2 {
            self.tkprp.expand_2to4(&mut buf, tree);
            tree[0..4].copy_from_slice(&buf[0..4]);
        } else {
            for i in (0..=sz - 4).rev().step_by(4) {
                self.tkprp.expand_4to8(&mut buf, &tree[i..]);
                tree[2 * i..2 * i + 8].copy_from_slice(&buf);
            }
        }
    }
}

#[test]
fn ggm_test() {
    use crate::ggm_tree::GgmTree;
    use crate::Block;

    let depth = 3;
    let mut tree = vec![Block::ZERO; 1 << depth];
    let mut k0 = vec![Block::ZERO; depth];
    let mut k1 = vec![Block::ZERO; depth];
    let mut k = vec![Block::ZERO; depth];
    let alpha = [false, true, false];
    let mut pos = 0;

    for a in alpha {
        pos <<= 1;
        if !a {
            pos += 1;
        }
    }

    let ggm = GgmTree::new(depth);

    ggm.gen(Block::ZERO, &mut tree, &mut k0, &mut k1);

    for i in 0..depth {
        if alpha[i] {
            k[i] = k1[i];
        } else {
            k[i] = k0[i];
        }
    }

    let mut tree_reconstruct = vec![Block::ZERO; 1 << depth];
    ggm.reconstruct(&mut tree_reconstruct, &k, &alpha);

    assert_eq!(tree_reconstruct[pos], Block::ZERO);
    tree_reconstruct[pos] = tree[pos];
    assert_eq!(tree, tree_reconstruct);
}
