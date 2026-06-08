//! Implement AES-based PRG.

use std::{collections::HashMap, convert::Infallible};

use crate::{Block, aes::AesEncryptor};
use rand::{Rng, RngExt};
use rand_core::{
    SeedableRng, TryCryptoRng, TryRng,
    block::{BlockRng, Generator},
};

/// Struct of PRG Core
#[derive(Clone)]
struct PrgCore {
    aes: AesEncryptor,
    // Stores the counter for each stream id.
    state: HashMap<u64, u64>,
    stream_id: u64,
    counter: u64,
}

impl Generator for PrgCore {
    type Output = [u32; 4 * AesEncryptor::AES_BLOCK_COUNT];

    // Compute 8 encrypted counter blocks at a time.
    #[inline(always)]
    fn generate(&mut self, results: &mut Self::Output) {
        let mut states = [0; AesEncryptor::AES_BLOCK_COUNT].map(
            #[inline(always)]
            |_| {
                let mut block = [0u8; 16];
                let counter = self.counter;
                self.counter += 1;

                block[..8].copy_from_slice(&counter.to_le_bytes());
                block[8..].copy_from_slice(&self.stream_id.to_le_bytes());

                Block::from(block)
            },
        );
        self.aes.encrypt_many_blocks(&mut states);
        *results = bytemuck::cast(states);
    }
}

impl SeedableRng for PrgCore {
    type Seed = Block;

    #[inline(always)]
    fn from_seed(seed: Self::Seed) -> Self {
        let aes = AesEncryptor::new(seed);
        Self {
            aes,
            state: Default::default(),
            stream_id: 0u64,
            counter: 0u64,
        }
    }
}

/// AES-based PRG.
///
/// This PRG is based on AES128 used in counter-mode to generate pseudo-random
/// data streams.
///
/// # Stream ID
///
/// The PRG is configurable with a stream ID, which can be used to generate
/// distinct streams using the same seed. See [`Prg::set_stream_id`].
#[derive(Clone)]
pub struct Prg(BlockRng<PrgCore>);

opaque_debug::implement!(Prg);

impl TryRng for Prg {
    type Error = Infallible;

    #[inline(always)]
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.0.next_word())
    }

    #[inline(always)]
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.0.next_u64_from_u32())
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for Prg {
    type Seed = Block;

    #[inline(always)]
    fn from_seed(seed: Self::Seed) -> Self {
        Prg(BlockRng::new(PrgCore::from_seed(seed)))
    }
}

impl TryCryptoRng for Prg {}

impl Prg {
    /// New Prg with random seed.
    #[inline(always)]
    pub fn new() -> Self {
        Prg::from_seed(rand::random::<Block>())
    }

    /// Create a new PRG from a seed.
    pub fn new_with_seed(seed: [u8; 16]) -> Self {
        Prg::from_seed(Block::from(seed))
    }

    /// Returns the current counter.
    pub fn counter(&self) -> u64 {
        self.0.core.counter
    }

    /// Returns the stream id.
    pub fn stream_id(&self) -> u64 {
        self.0.core.stream_id
    }

    /// Sets the stream id.
    pub fn set_stream_id(&mut self, stream_id: u64) {
        let state = &mut self.0.core.state;
        state.insert(self.0.core.stream_id, self.0.core.counter);

        let counter = state.get(&stream_id).copied().unwrap_or(0);

        self.0.core.stream_id = stream_id;
        self.0.core.counter = counter;
    }

    /// Generate a random bool value.
    #[inline(always)]
    pub fn random_bool(&mut self) -> bool {
        self.random()
    }

    /// Fill a bool slice with random bool values.
    #[inline(always)]
    pub fn random_bools(&mut self, buf: &mut [bool]) {
        for b in buf {
            *b = self.random();
        }
    }

    /// Generate a random byte value.
    #[inline(always)]
    pub fn random_byte(&mut self) -> u8 {
        self.random()
    }

    /// Fill a byte slice with random values.
    #[inline(always)]
    pub fn random_bytes(&mut self, buf: &mut [u8]) {
        self.fill_bytes(buf);
    }

    /// Generate a random block.
    #[inline(always)]
    pub fn random_block(&mut self) -> Block {
        self.random()
    }

    /// Fill a block slice with random block values.
    #[inline(always)]
    pub fn random_blocks(&mut self, buf: &mut [Block]) {
        let bytes: &mut [u8] = bytemuck::cast_slice_mut(buf);
        self.fill_bytes(bytes);
    }

    /// Fills `buf` with the same pseudo-random block stream that
    /// `Prg::from_seed(seed).random_blocks(buf)` would produce, but computed in
    /// parallel.
    ///
    /// The PRG is AES in counter mode, so block `i` is
    /// `AES_seed(i ‖ stream_id=0)` and can be generated independently. With the
    /// `rayon` feature disabled this falls back to the sequential path and
    /// produces byte-identical output.
    pub fn random_blocks_par(seed: Block, buf: &mut [Block]) {
        #[inline]
        fn fill_chunk(aes: &AesEncryptor, start: u64, chunk: &mut [Block]) {
            for (j, blk) in chunk.iter_mut().enumerate() {
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&(start + j as u64).to_le_bytes());
                // stream_id == 0, so the high 8 bytes stay zero.
                *blk = Block::from(b);
            }
            aes.encrypt_blocks(chunk);
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                use rayon::prelude::*;

                const CHUNK: usize = 1 << 14;
                let aes = AesEncryptor::new(seed);
                buf.par_chunks_mut(CHUNK).enumerate().for_each(|(ci, chunk)| {
                    fill_chunk(&aes, (ci * CHUNK) as u64, chunk);
                });
            } else {
                let aes = AesEncryptor::new(seed);
                fill_chunk(&aes, 0, buf);
            }
        }
    }

    /// Computes the GF(2^128) inner product `Σ_i chi_i · b_i`, where `chi` is
    /// the block stream of `Prg::from_seed(seed)` (matching `random_blocks`
    /// and `random_blocks_par`).
    ///
    /// `chi` is regenerated on the fly in counter mode and never materialized,
    /// so only `b` is streamed from memory — this avoids both the allocation
    /// and the write+read round-trip of an explicit `chi` vector. The
    /// result is identical to `Block::inn_prdt_red(&chi, b)`. With the
    /// `rayon` feature the product is computed over parallel chunks and
    /// reduced once at the end.
    pub fn chi_inner_product(seed: Block, b: &[Block]) -> Block {
        let aes = AesEncryptor::new(seed);

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                use rayon::prelude::*;

                const CHUNK: usize = 1 << 16;
                let (hi, lo) = if b.len() <= CHUNK {
                    chi_clmul_acc(&aes, 0, b)
                } else {
                    b.par_chunks(CHUNK)
                        .enumerate()
                        .map(|(ci, chunk)| chi_clmul_acc(&aes, (ci * CHUNK) as u64, chunk))
                        .reduce(
                            || (Block::ZERO, Block::ZERO),
                            |p, q| (p.0 ^ q.0, p.1 ^ q.1),
                        )
                };
            } else {
                let (hi, lo) = chi_clmul_acc(&aes, 0, b);
            }
        }

        Block::reduce_gcm(hi, lo)
    }

    /// Fills `out[j]` with the block at counter index `positions[j]` of the
    /// `Prg::from_seed(seed)` stream (stream id 0), i.e. the same value as
    /// `random_blocks(buf)[positions[j]]`.
    ///
    /// # Panics
    ///
    /// Panics if `out.len() != positions.len()`.
    pub fn blocks_at(seed: Block, positions: &[usize], out: &mut [Block]) {
        assert_eq!(positions.len(), out.len());
        let aes = AesEncryptor::new(seed);
        for (o, &p) in out.iter_mut().zip(positions) {
            let mut blk = [0u8; 16];
            blk[..8].copy_from_slice(&(p as u64).to_le_bytes());
            *o = Block::from(blk);
        }
        aes.encrypt_blocks(out);
    }
}

/// Accumulates the unreduced inner product `Σ chi_{start+j} · b[j]`, generating
/// `chi` in counter mode in small cache-resident batches and using 8
/// independent accumulators to break the `clmul` latency-dependency chain.
#[inline]
fn chi_clmul_acc(aes: &AesEncryptor, start: u64, b: &[Block]) -> (Block, Block) {
    const BATCH: usize = 256;
    let mut hi = [Block::ZERO; 8];
    let mut lo = [Block::ZERO; 8];
    let mut chi = [Block::ZERO; BATCH];

    let mut off = 0usize;
    while off < b.len() {
        let len = BATCH.min(b.len() - off);

        // Generate this batch of chi blocks (counter mode, stream id 0).
        for (j, c) in chi[..len].iter_mut().enumerate() {
            let mut blk = [0u8; 16];
            blk[..8].copy_from_slice(&(start + (off + j) as u64).to_le_bytes());
            *c = Block::from(blk);
        }
        aes.encrypt_blocks(&mut chi[..len]);

        let bc = &b[off..off + len];
        let mut k = 0;
        while k + 8 <= len {
            for j in 0..8 {
                let (h, l) = chi[k + j].clmul(bc[k + j]);
                hi[j] ^= h;
                lo[j] ^= l;
            }
            k += 8;
        }
        for j in k..len {
            let (h, l) = chi[j].clmul(bc[j]);
            hi[0] ^= h;
            lo[0] ^= l;
        }

        off += len;
    }

    let mut acc_hi = Block::ZERO;
    let mut acc_lo = Block::ZERO;
    for j in 0..8 {
        acc_hi ^= hi[j];
        acc_lo ^= lo[j];
    }
    (acc_hi, acc_lo)
}

impl Default for Prg {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prg_ne() {
        let mut prg = Prg::new();
        let mut x = vec![Block::ZERO; 2];
        prg.random_blocks(&mut x);
        assert_ne!(x[0], x[1]);
    }

    #[test]
    fn test_prg_streams_are_distinct() {
        let mut prg = Prg::from_seed(Block::ZERO);
        let mut x = vec![Block::ZERO; 2];
        prg.random_blocks(&mut x);

        let mut y = vec![Block::ZERO; 2];
        prg.set_stream_id(1);
        prg.random_blocks(&mut y);

        assert_ne!(x[0], y[0]);
    }

    #[test]
    fn test_random_blocks_par_matches_sequential() {
        let seed = Block::from(*b"0123456789abcdef");
        // Cover non-multiples of the 8-block AES batch and the rayon chunk.
        for len in [0usize, 1, 7, 8, 9, 100, 1023, 16384, 16385, 40000] {
            let mut seq = vec![Block::ZERO; len];
            Prg::from_seed(seed).random_blocks(&mut seq);

            let mut par = vec![Block::ZERO; len];
            Prg::random_blocks_par(seed, &mut par);

            assert_eq!(seq, par, "mismatch at len {len}");
        }
    }

    #[test]
    fn test_chi_inner_product_matches_explicit() {
        let seed = Block::from(*b"chi_seed_0123456");
        let mut src = Prg::from_seed(Block::from(*b"vs_seed_abcdefgh"));
        for len in [0usize, 1, 7, 8, 9, 255, 256, 257, 1000, 70_000] {
            let mut b = vec![Block::ZERO; len];
            src.random_blocks(&mut b);

            let mut chis = vec![Block::ZERO; len];
            Prg::random_blocks_par(seed, &mut chis);
            let expected = Block::inn_prdt_red(&chis, &b);

            assert_eq!(expected, Prg::chi_inner_product(seed, &b), "len {len}");
        }
    }

    #[test]
    fn test_blocks_at_matches_stream() {
        let seed = Block::from(*b"some_seed_012345");
        let n = 2048;
        let mut full = vec![Block::ZERO; n];
        Prg::from_seed(seed).random_blocks(&mut full);

        let positions = [0usize, 1, 5, 8, 100, 255, 256, 1023, 2047];
        let mut out = vec![Block::ZERO; positions.len()];
        Prg::blocks_at(seed, &positions, &mut out);

        for (o, &p) in out.iter().zip(&positions) {
            assert_eq!(*o, full[p], "position {p}");
        }
    }

    #[test]
    fn test_prg_state_persisted() {
        let mut prg = Prg::from_seed(Block::ZERO);
        let mut x = vec![Block::ZERO; 2];
        prg.random_blocks(&mut x);

        let counter = prg.counter();
        assert_ne!(counter, 0);

        prg.set_stream_id(1);
        prg.set_stream_id(0);

        assert_eq!(prg.counter(), counter);
    }
}
