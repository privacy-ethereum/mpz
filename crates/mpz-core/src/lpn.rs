//! Implement LPN with local linear code.
//! More specifically, a local linear code is a random boolean matrix with at most D non-zero values in each row.

use crate::{prp::Prp, Block};
use rand::{seq::SliceRandom, thread_rng};
use rayon::prelude::*;
/// An LPN encoder.
///
/// The `seed` defines a sparse binary matrix `A` with at most `D` non-zero values in each row.
///
/// Given a vector `x` and `e`, compute `y = Ax + e`.
///
/// `A` - is a binary matrix with `k` columns and `n` rows. The concrete number of `n` is determined by the input length. `A` will be generated on-the-fly.
///
/// `x` - is a `F_{2^128}` vector with length `k`.
///
/// `e` - is a `F_{2^128}` vector with length `n`.
///
/// Note that in the standard LPN problem, `x` is a binary vector, `e` is a sparse binary vector. The way we defined here is a more generic way in term of computing `y`.
pub struct LpnEncoder<const D: usize> {
    /// The seed to generate the random sparse matrix A.
    seed: Block,

    /// The length of the secret, i.e., x.
    k: u32,

    /// A mask to optimize reduction operation.
    mask: u32,
}

impl<const D: usize> LpnEncoder<D> {
    /// Create a new LPN instance.
    pub fn new(seed: Block, k: u32) -> Self {
        let mut mask = 1;
        while mask < k {
            mask <<= 1;
            mask |= 0x1;
        }
        Self { seed, k, mask }
    }

    /// Compute 4 rows as a batch, this is for the `compute` function.
    #[inline]
    fn compute_four_rows_indep(&self, y: &mut [Block], x: &[Block], pos: usize, prp: &Prp) {
        let mut cnt = 0u64;
        let mut index: [Block; D] = std::array::from_fn(|_| {
            let i = cnt;
            cnt += 1;
            Block::from(bytemuck::cast::<_, [u8; 16]>([pos as u64, i]))
        });

        prp.permute_many_blocks(&mut index);
        let index = bytemuck::cast_slice_mut::<_, u32>(&mut index);

        for (i, y) in y.iter_mut().enumerate().take(4) {
            for ind in index[i * D..(i + 1) * D].iter_mut() {
                *ind &= self.mask;
                *ind = if *ind >= self.k { *ind - self.k } else { *ind };

                *y ^= x[*ind as usize];
            }
        }
    }

    #[inline]
    fn compute_one_row(&self, y: &mut [Block], x: &[Block], pos: usize, prp: &Prp) {
        let block_size = D.div_ceil(4);
        let mut index = (0..block_size)
            .map(|i| Block::from(bytemuck::cast::<_, [u8; 16]>([pos as u64, i as u64])))
            .collect::<Vec<Block>>();
        prp.permute_block_inplace(&mut index);
        let index = bytemuck::cast_slice_mut::<_, u32>(&mut index);

        for ind in index.iter_mut().take(D) {
            *ind &= self.mask;
            *ind = if *ind >= self.k { *ind - self.k } else { *ind };
            y[pos] ^= x[*ind as usize];
        }
    }

    /// Compute `Ax + e`, writing the result in-place into `y`.
    ///
    /// # Arguments
    ///
    /// * `x` - Secret vector with length `k`.
    /// * `y` - Error vector with length `n`, this is actually `e` in LPN.
    ///
    /// # Panics
    ///
    /// Panics if `x.len() !=k` or `y.len() != n`.
    pub fn compute(&self, y: &mut [Block], x: &[Block]) {
        assert_eq!(x.len() as u32, self.k);
        assert!(x.len() >= D);
        let prp = Prp::new(self.seed);
        let size = y.len() - (y.len() % 4);

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")]{
                let iter = y.par_chunks_exact_mut(4).enumerate();
            }else{
                let iter = y.chunks_exact_mut(4).enumerate();
            }
        }

        iter.for_each(|(i, y)| {
            self.compute_four_rows_indep(y, x, i * 4, &prp);
        });

        for i in size..y.len() {
            self.compute_one_row(y, x, i, &prp);
        }
    }
}

/// Lpn paramters
#[derive(Copy, Clone, Debug)]
pub struct LpnParameters {
    /// The length of output vecotrs.
    pub n: usize,
    /// The length of the secret vector
    pub k: usize,
    /// The Hamming Weight of error vectors
    pub t: usize,
}

impl LpnParameters {
    /// Create a new LpnParameters instance.
    pub fn new(n: usize, k: usize, t: usize) -> Self {
        assert!(t <= n);
        LpnParameters { n, k, t }
    }

    /// Sample a uniform error vector with HW t.
    pub fn sample_uniform_error_vector(&self) -> Vec<Block> {
        let one: Block = bytemuck::cast(1_u128);
        let mut res = vec![Block::ZERO; self.n];
        res[0..self.t].iter_mut().for_each(|x| *x = one);
        let mut rng = thread_rng();
        res.shuffle(&mut rng);
        res
    }

    /// Sample a regular error vector with HW t
    pub fn sample_regular_error_vector(&self) -> Vec<Block> {
        assert_eq!(self.n % self.t, 0);
        let one: Block = bytemuck::cast(1_u128);
        let mut res = vec![Block::ZERO; self.n];
        let mut rng = thread_rng();

        res.chunks_exact_mut(self.n / self.t).for_each(|x| {
            x[0] = one;
            x.shuffle(&mut rng);
        });
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::lpn::LpnEncoder;
    use crate::prp::Prp;
    use crate::Block;

    impl<const D: usize> LpnEncoder<D> {
        #[allow(dead_code)]
        fn compute_four_rows_non_indep(&self, y: &mut [Block], x: &[Block], pos: usize, prp: &Prp) {
            let mut cnt = 0u64;
            let mut index = [0; D].map(|_| {
                let i: u64 = cnt;
                cnt += 1;
                Block::from(bytemuck::cast::<_, [u8; 16]>([pos as u64, i]))
            });

            prp.permute_many_blocks(&mut index);
            let index: &mut [u32] = bytemuck::cast_slice_mut::<_, u32>(&mut index);

            for (i, y) in y[pos..].iter_mut().enumerate().take(4) {
                for ind in index[i * D..(i + 1) * D].iter_mut() {
                    *ind &= self.mask;
                    *ind = if *ind >= self.k { *ind - self.k } else { *ind };

                    *y ^= x[*ind as usize];
                }
            }
        }

        #[allow(dead_code)]
        pub(crate) fn compute_naive(&self, y: &mut [Block], x: &[Block]) {
            assert_eq!(x.len() as u32, self.k);
            assert!(x.len() >= D);
            let prp = Prp::new(self.seed);
            let batch_size = y.len() / 4;

            for i in 0..batch_size {
                self.compute_four_rows_non_indep(y, x, i * 4, &prp);
            }

            for i in batch_size * 4..y.len() {
                self.compute_one_row(y, x, i, &prp);
            }
        }
    }

    #[test]
    fn lpn_test() {
        use crate::lpn::LpnEncoder;
        use crate::prg::Prg;
        use crate::Block;

        let k = 20;
        let n = 200;
        let lpn = LpnEncoder::<10>::new(Block::ZERO, k);
        let mut x = vec![Block::ONES; k as usize];
        let mut y = vec![Block::ONES; n];
        let mut prg = Prg::new();
        prg.random_blocks(&mut x);
        prg.random_blocks(&mut y);
        let mut z = y.clone();

        lpn.compute_naive(&mut y, &x);
        lpn.compute(&mut z, &x);

        assert_eq!(y, z);
    }
}
