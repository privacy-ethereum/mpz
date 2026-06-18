use std::{collections::VecDeque, mem};

use crate::{
    TransferId,
    softspoken::{
        CSP, Check, Corrections, Extend, SSP, SenderConfig, SenderError, check, fold,
        fold::TILE_TARGET_BLOCKS, ggm,
    },
    rcot::{RCOTSender, RCOTSenderOutput},
};

use itybity::ToBits;
use mpz_common::future::{MaybeDone, Sender as OutputSender, new_output};
use mpz_core::{Block, aes::FixedKeyAes};
use mpz_fields::{ExtensionField, gf2::Gf2};

use rand::{Rng as _, rng};

use zerocopy::{FromBytes, IntoBytes};

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// Stretches and folds one punctured VOLE block of this batch into the shared
/// MAC matrix, deriving the keys in place.
///
/// `slab` is the block's `k` contiguous matrix rows; `us_row` is the block's
/// received derandomization `ū_b`. `delta_bits` are the block's `k` delta bits.
#[allow(clippy::too_many_arguments)]
fn fold_block(
    aes: &FixedKeyAes,
    leaves: &[[u8; 16]],
    slab: &mut [u8],
    us_row: &[u8],
    src: &mut [[u8; 16]],
    scratch: &mut [[u8; 16]],
    u_tile: &mut [u8],
    t_b: &mut [u8],
    missing: usize,
    delta_bits: &[bool],
    k: usize,
    total_rb: usize,
    filled: usize,
    m: usize,
    tile_blocks: usize,
) {
    let q = 1 << k;
    let mut tc = 0;
    while tc < m {
        let tw = tile_blocks.min(m - tc);
        let tb = tw * 16;
        let ctr = (filled + tc) as u64;
        fold::stretch(aes, leaves, tw, ctr, src, scratch);
        // The punctured leaf contributes nothing to the fold.
        scratch[missing * tw..(missing + 1) * tw].fill([0u8; 16]);

        let col = (filled + tc) * 16;
        fold::fold_emit(
            &mut scratch.as_mut_bytes()[..q * tb],
            tb,
            k,
            slab,
            total_rb,
            col,
            &mut u_tile[..tb],
        );

        // t_b = u_b ⊕ ū_b, then w_i = v_i ⊕ bit_i(Δ_b)·t_b. The delta bit is
        // applied as an arithmetic mask so the key derivation is constant-time
        // w.r.t. delta.
        t_b[..tb].copy_from_slice(&u_tile[..tb]);
        fold::xor_into(&mut t_b[..tb], &us_row[tc * 16..tc * 16 + tb]);
        for i in 0..k {
            let mask = [0u8.wrapping_sub(delta_bits[i] as u8); 16];
            fold::xor_masked_into(
                &mut slab[i * total_rb + col..i * total_rb + col + tb],
                &t_b[..tb],
                mask,
            );
        }
        tc += tw;
    }
}

#[derive(Debug)]
struct Queued {
    count: usize,
    sender: OutputSender<RCOTSenderOutput<Block>>,
}

/// SoftSpoken sender.
#[derive(Debug)]
pub struct Sender<T: state::State = state::Initialized> {
    config: SenderConfig,
    alloc: usize,
    queue: VecDeque<Queued>,
    transfer_id: TransferId,
    delta: Block,
    state: T,
}

impl<T> Sender<T>
where
    T: state::State,
{
    /// Returns the Sender's configuration
    pub fn config(&self) -> &SenderConfig {
        &self.config
    }
}

impl Sender<state::Initialized> {
    /// Creates a new sender with the global COT correlation `delta`.
    pub fn new(config: SenderConfig, delta: Block) -> Self {
        Sender {
            config,
            // SSP extra OTs are sacrificed to the consistency check.
            alloc: SSP,
            transfer_id: TransferId::default(),
            queue: VecDeque::default(),
            delta,
            state: state::Initialized::default(),
        }
    }

    /// Loads the base-OT seeds (chosen by `delta`), advancing to the
    /// `corrections` step.
    pub fn setup(self, seeds: [Block; CSP]) -> Sender<state::Setup> {
        Sender {
            config: self.config,
            alloc: self.alloc,
            transfer_id: self.transfer_id,
            queue: self.queue,
            delta: self.delta,
            state: state::Setup {
                singles: seeds.iter().map(|s| s.to_bytes()).collect(),
            },
        }
    }
}

impl Sender<state::Setup> {
    /// Reconstructs the punctured GGM trees from the receiver's tree
    /// corrections, transitioning to the extension phase.
    pub fn corrections(self, corrections: Corrections) -> Sender<state::Extension> {
        let k = self.config.k();
        let n_blocks = self.config.n_blocks();
        let q = self.config.leaves();

        let Corrections { corrections, s } = corrections;
        let hasher = FixedKeyAes::new(s);
        let delta_bits: Vec<bool> = self.delta.iter_lsb0().collect();
        let singles = self.state.singles;
        let aes = ggm::expander();
        let mut leaf_seeds = vec![[0u8; 16]; n_blocks * q];
        let mut missing = vec![0usize; n_blocks];
        let mut parents = vec![[0u8; 16]; q / 2];
        for b in 0..n_blocks {
            // The missing leaf of block `b` is the `delta` chunk
            // `bits[b*k .. b*k + k]`.
            let mut idx = 0;
            for i in 0..k {
                if delta_bits[b * k + i] {
                    idx |= 1 << i;
                }
            }
            ggm::build_punctured(
                &aes,
                idx,
                &singles[b * k..b * k + k],
                &corrections[2 * k * b..2 * k * (b + 1)],
                &mut leaf_seeds[b * q..(b + 1) * q],
                &mut parents,
            );
            missing[b] = idx;
        }

        Sender {
            config: self.config,
            alloc: self.alloc,
            transfer_id: self.transfer_id,
            queue: self.queue,
            delta: self.delta,
            state: state::Extension {
                hasher,
                leaf_seeds,
                missing,
                mac: Vec::default(),
                total_rb: 0,
                filled: 0,
                out_total: 0,
                consumed: 0,
                extended: false,
                chi: None,
            },
        }
    }
}

impl Sender<state::Extension> {
    /// Returns `true` if the sender wants to extend.
    pub fn wants_extend(&self) -> bool {
        self.alloc != 0
    }

    /// Returns `true` if the sender wants to run the consistency check.
    pub fn wants_check(&self) -> bool {
        self.alloc == 0 && !self.state.extended && !self.state.mac.is_empty()
    }

    /// Processes one extension batch from the receiver's [`Extend`] message.
    pub fn extend(&mut self, extend: Extend) -> Result<(), SenderError> {
        if self.state.extended {
            return Err(SenderError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        let Extend { count, us } = extend;

        let k = self.config.k();
        let n_blocks = self.config.n_blocks();
        let q = self.config.leaves();

        // Round up to a multiple of SSP (the rows sacrificed to the check).
        let expected_count = self.config.batch_size().min(self.alloc).next_multiple_of(SSP);
        if count != expected_count {
            return Err(SenderError::CountMismatch {
                expected: expected_count,
                actual: count,
            });
        }

        let rb = count / 8;
        let m = count / CSP; // blocks per row this batch

        if us.len() != n_blocks * rb {
            return Err(SenderError::InvalidExtend);
        }

        // First extend: size the matrix from the (now final) demand. The
        // punctured trees were built in the `corrections` transition.
        if self.state.mac.is_empty() {
            let total = self.alloc.next_multiple_of(SSP);
            self.state.total_rb = total / 8;
            self.state.mac = vec![0u8; CSP * self.state.total_rb];
        }

        let delta_bits: Vec<bool> = self.delta.iter_lsb0().collect();

        let total_rb = self.state.total_rb;
        let filled = self.state.filled;
        let tile_blocks = (TILE_TARGET_BLOCKS / q).max(1).min(m);

        let hasher = &self.state.hasher;
        let leaf_seeds = &self.state.leaf_seeds;
        let missing = &self.state.missing;
        let mac = &mut self.state.mac;
        let delta_bits = &delta_bits;
        let make_buf = || {
            (
                vec![[0u8; 16]; q * tile_blocks],
                vec![[0u8; 16]; q * tile_blocks],
                vec![0u8; tile_blocks * 16],
                vec![0u8; tile_blocks * 16],
            )
        };

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                leaf_seeds
                    .par_chunks(q)
                    .zip(mac.par_chunks_mut(k * total_rb))
                    .zip(us.par_chunks(rb))
                    .enumerate()
                    .for_each_init(make_buf, |(src, scratch, u_tile, t_b), (b, ((leaves, slab), us_row))| {
                        fold_block(
                            hasher, leaves, slab, us_row, src, scratch, u_tile, t_b, missing[b],
                            &delta_bits[b * k..b * k + k], k, total_rb, filled, m, tile_blocks,
                        );
                    });
            } else {
                let (mut src, mut scratch, mut u_tile, mut t_b) = make_buf();
                leaf_seeds
                    .chunks(q)
                    .zip(mac.chunks_mut(k * total_rb))
                    .zip(us.chunks(rb))
                    .enumerate()
                    .for_each(|(b, ((leaves, slab), us_row))| {
                        fold_block(
                            hasher, leaves, slab, us_row, &mut src, &mut scratch, &mut u_tile,
                            &mut t_b, missing[b], &delta_bits[b * k..b * k + k], k, total_rb, filled,
                            m, tile_blocks,
                        );
                    });
            }
        }

        self.state.filled = filled + m;
        self.alloc = self.alloc.saturating_sub(count);

        Ok(())
    }

    /// Starts the consistency check by sampling a random seed.
    pub fn check_start(&mut self) -> Block {
        let chi = rng().random::<Block>();
        self.state.chi = Some(chi);
        chi
    }

    /// Verifies the receiver's [`Check`] and, on success, finalizes the OTs.
    pub fn check(&mut self, receiver_check: Check) -> Result<(), SenderError> {
        if !self.wants_check() {
            return Err(SenderError::InvalidState("not ready to check".to_string()));
        }
        let chi_seed = mem::take(&mut self.state.chi).ok_or(SenderError::ChiNotSet)?;

        let total_rb = self.state.total_rb;

        let (check_q, _) = check::check_fold(chi_seed, &self.state.mac, total_rb, None);

        let Check { x, t } = receiver_check;

        // Constant-time verify: accumulate every row's inequality into one flag
        // with no early return, so only the final pass/fail — the protocol's
        // modeled selective-abort leak — is exposed.
        let mut failed = false;
        for ((bit, t), q) in self.delta.iter_lsb0().zip(t).zip(check_q) {
            let xb = x.scale_by_subfield(Gf2(bit));
            failed |= q != t + xb;
        }
        if failed {
            return Err(SenderError::ConsistencyCheckFailed);
        }

        // Transpose the matrix in place: it becomes the per-OT keys. The last
        // SSP OTs are sacrificed to the check.
        matrix_transpose::transpose_bits(&mut self.state.mac, CSP).expect("matrix is rectangular");
        self.state.out_total = total_rb * 8 - SSP;
        self.state.extended = true;

        // Resolve any queued transfers.
        for Queued { count, sender } in mem::take(&mut self.queue) {
            let keys = self.take_keys(count);
            sender.send(RCOTSenderOutput {
                id: self.transfer_id.next(),
                keys,
            });
        }

        Ok(())
    }

    /// Consumes `count` checked keys from the transposed matrix.
    fn take_keys(&mut self, count: usize) -> Vec<Block> {
        let start = self.state.consumed;
        let keys = <[Block]>::ref_from_bytes(&self.state.mac[start * 16..(start + count) * 16])
            .expect("multiple of Block size")
            .to_vec();
        self.state.consumed += count;
        keys
    }
}

impl RCOTSender<Block> for Sender<state::Initialized> {
    type Error = SenderError;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        0
    }

    fn delta(&self) -> Block {
        self.delta
    }

    fn try_send_rcot(&mut self, _count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        Err(SenderError::InvalidState(
            "sender has not been setup yet".to_string(),
        ))
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.queue.push_back(Queued { count, sender });

        Ok(recv)
    }
}

impl RCOTSender<Block> for Sender<state::Extension> {
    type Error = SenderError;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.state.extended {
            return Err(SenderError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        self.state.out_total - self.state.consumed
    }

    fn delta(&self) -> Block {
        self.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        if self.available() < count {
            return Err(SenderError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            });
        }

        let keys = self.take_keys(count);

        Ok(RCOTSenderOutput {
            id: self.transfer_id.next(),
            keys,
        })
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.available() >= count {
            let output = self.try_send_rcot(count)?;
            let (sender, recv) = new_output();
            sender.send(output);

            Ok(recv)
        } else if !self.state.extended {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            Ok(recv)
        } else {
            Err(SenderError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            })
        }
    }
}

/// The sender's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Setup {}
        impl Sealed for super::Extension {}
    }

    /// The sender's state.
    pub trait State: sealed::Sealed {}

    /// The sender's initial state.
    #[derive(Default)]
    pub struct Initialized {}

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The sender's state after base OT, holding the chosen seeds until the
    /// tree corrections arrive.
    pub struct Setup {
        /// Base-OT seeds chosen by `delta`.
        pub(super) singles: Vec<[u8; 16]>,
    }

    impl State for Setup {}

    opaque_debug::implement!(Setup);

    /// The sender's state after the setup phase.
    pub struct Extension {
        /// Per-instance MMO hash for the leaf stretch (keyed by the seed `s`).
        pub(super) hasher: mpz_core::aes::FixedKeyAes,
        /// GGM leaf seeds (`n_blocks * 2^k`); the missing leaf of each block is
        /// zero and skipped in the fold.
        pub(super) leaf_seeds: Vec<[u8; 16]>,
        /// Missing (punctured) leaf index of each block.
        pub(super) missing: Vec<usize>,
        /// The single MAC matrix: `CSP × total_rb` bytes, row-major. Filled
        /// during extension, then transposed in place to the per-OT keys at the
        /// consistency check.
        pub(super) mac: Vec<u8>,
        /// Width of one matrix row in bytes.
        pub(super) total_rb: usize,
        /// Blocks filled per row so far (also the PRG stretch counter).
        pub(super) filled: usize,
        /// Number of valid (non-sacrificial) OTs available after the check.
        pub(super) out_total: usize,
        /// Number of OTs consumed from the output.
        pub(super) consumed: usize,
        /// Whether extension has completed (the check has run).
        pub(super) extended: bool,
        /// A seed for the random weights χ for the consistency check.
        pub(super) chi: Option<Block>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
