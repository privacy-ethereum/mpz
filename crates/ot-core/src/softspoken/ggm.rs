//! Binary GGM tree for the SoftSpoken small-field VOLE.
//!
//! Each VOLE block is a depth-`k` tree that the receiver builds in full and the
//! sender reconstructs except for the leaf on the path selected by its `delta`
//! chunk. Children are derived with a two-key fixed-key AES MMO; per-level
//! corrections from the receiver let the sender fill in its one missing node.
//! The split layout indexes a leaf by its path (level-1 bit least significant),
//! so the missing index is exactly the `delta` chunk.

use mpz_core::aes::FixedKeyAes;

use crate::softspoken::fold::xor16;

/// Number of corrections emitted per tree level (one per child side).
const SIDES: usize = 2;

/// A 16-byte GGM node / PRG seed.
type Node = [u8; 16];

/// Fixed public keys for the two-key expansion PRP.
const GGM_KEY0: [u8; 16] = *b"mpz-softspoken-0";
const GGM_KEY1: [u8; 16] = *b"mpz-softspoken-1";

/// Creates the two-key fixed-key AES expander.
pub(crate) fn expander() -> [FixedKeyAes; 2] {
    [FixedKeyAes::new(GGM_KEY0), FixedKeyAes::new(GGM_KEY1)]
}

/// Expands level `l-1` (the first `n` entries of `nodes`) into level `l` in the
/// split layout, using `parents` as scratch for the saved parents.
fn expand_level(aes: &[FixedKeyAes; 2], nodes: &mut [Node], n: usize, parents: &mut [Node]) {
    parents[..n].copy_from_slice(&nodes[..n]);
    aes[0].mmo_blocks_to(&parents[..n], &mut nodes[..n]); // left children
    aes[1].mmo_blocks_to(&parents[..n], &mut nodes[n..2 * n]); // right children
}

fn xor_all(nodes: &[Node]) -> Node {
    nodes.iter().fold([0u8; 16], |acc, &x| xor16(acc, x))
}

/// Builds the full GGM tree from `root`, writing the `2^k` leaves into `out`
/// and the `2 * k` corrections into `corr`.
///
/// `pairs` are the `k` base-OT seed pairs; `parents` is reused scratch of at
/// least `2^(k-1)` nodes.
pub(crate) fn build_full(
    aes: &[FixedKeyAes; 2],
    root: Node,
    pairs: &[[Node; 2]],
    out: &mut [Node],
    corr: &mut [Node],
    parents: &mut [Node],
) {
    let k = pairs.len();
    debug_assert_eq!(out.len(), 1 << k);
    debug_assert_eq!(corr.len(), SIDES * k);

    out[0] = root;
    for l in 1..=k {
        let n = 1 << (l - 1);
        expand_level(aes, &mut out[..2 * n], n, parents);

        let sum0 = xor_all(&out[..n]);
        let sum1 = xor_all(&out[n..2 * n]);
        // Pad each side's sum with the base seed for the opposite choice, so
        // the sender's held seed decrypts exactly the sibling side it needs.
        corr[SIDES * (l - 1)] = xor16(sum0, pairs[l - 1][1]);
        corr[SIDES * (l - 1) + 1] = xor16(sum1, pairs[l - 1][0]);
    }
}

/// Reconstructs every leaf except the one at `missing` (set to zero), writing
/// them into `out`.
///
/// `singles[i]` is the base-OT seed `pair[i][bit_i(missing)]` held by the
/// sender, `corr` is the message from [`build_full`], and `parents` is reused
/// scratch of at least `2^(k-1)` nodes.
pub(crate) fn build_punctured(
    aes: &[FixedKeyAes; 2],
    missing: usize,
    singles: &[Node],
    corr: &[Node],
    out: &mut [Node],
    parents: &mut [Node],
) {
    let k = singles.len();
    debug_assert_eq!(out.len(), 1 << k);
    debug_assert_eq!(corr.len(), SIDES * k);
    debug_assert!(missing < (1 << k));

    // Level 1: the sender recovers the single off-path node directly.
    let p = missing & 1;
    out[1 - p] = xor16(corr[1 - p], singles[0]);
    // `a` is the index of the (still unknown) on-path node at the current level.
    let mut a = p;

    for l in 2..=k {
        let n = 1 << (l - 1);
        // Expand every parent (including the junk node `a`, whose children are
        // overwritten below).
        expand_level(aes, &mut out[..2 * n], n, parents);

        // Recover the sibling of the unknown node: side `1 - p`, index
        // `a + (1 - p) * n`. The on-path child (side `p`) stays junk.
        let p = (missing >> (l - 1)) & 1;
        let sib = a + (1 - p) * n;
        let side_start = (1 - p) * n;
        let sum_side = xor16(corr[SIDES * (l - 1) + (1 - p)], singles[l - 1]);
        let mut known = [0u8; 16];
        for idx in side_start..side_start + n {
            if idx != sib {
                known = xor16(known, out[idx]);
            }
        }
        out[sib] = xor16(sum_side, known);

        a += p * n;
    }

    debug_assert_eq!(a, missing);
    out[missing] = [0u8; 16];
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    #[test]
    fn test_ggm_punctured_matches_full() {
        let mut rng = StdRng::seed_from_u64(0);
        let aes = expander();

        for k in [2usize, 4, 8] {
            let q = 1 << k;
            let root: Node = rng.random();
            let pairs: Vec<[Node; 2]> = (0..k).map(|_| [rng.random(), rng.random()]).collect();

            let mut full = vec![[0u8; 16]; q];
            let mut corr = vec![[0u8; 16]; 2 * k];
            let mut parents = vec![[0u8; 16]; q / 2];
            build_full(&aes, root, &pairs, &mut full, &mut corr, &mut parents);

            for missing in 0..q {
                let singles: Vec<Node> = (0..k).map(|i| pairs[i][(missing >> i) & 1]).collect();

                let mut punctured = vec![[0u8; 16]; q];
                build_punctured(&aes, missing, &singles, &corr, &mut punctured, &mut parents);

                for (idx, (&f, &p)) in full.iter().zip(&punctured).enumerate() {
                    if idx == missing {
                        assert_eq!(p, [0u8; 16], "missing leaf must be zero");
                    } else {
                        assert_eq!(f, p, "k={k} missing={missing} leaf {idx} mismatch");
                    }
                }
            }
        }
    }
}
