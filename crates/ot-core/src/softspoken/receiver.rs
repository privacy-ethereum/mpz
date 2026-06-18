use std::{collections::VecDeque, mem};

use crate::{
    TransferId,
    softspoken::{
        CSP, Check, Corrections, Extend, ReceiverConfig, ReceiverError, SSP, check, fold,
        fold::TILE_TARGET_BLOCKS, ggm,
    },
    rcot::{RCOTReceiver, RCOTReceiverOutput},
};

use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_core::{Block, aes::FixedKeyAes};

use rand::Rng as _;
use rand_core::RngCore;
use zerocopy::{FromBytes, IntoBytes};

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// Stretches and folds one VOLE block of this batch into the shared MAC matrix.
///
/// `slab` is the block's `k` contiguous matrix rows (`k * total_rb` bytes);
/// `us_row` is the block's `rb`-byte derandomization output. `src`/`scratch`/
/// `u_tile` are reused per-worker buffers.
#[allow(clippy::too_many_arguments)]
fn fold_block(
    aes: &FixedKeyAes,
    leaves: &[[u8; 16]],
    slab: &mut [u8],
    us_row: &mut [u8],
    src: &mut [[u8; 16]],
    scratch: &mut [[u8; 16]],
    u_tile: &mut [u8],
    k: usize,
    total_rb: usize,
    filled: usize,
    m: usize,
    tile_blocks: usize,
    choices: &[u8],
) {
    let q = 1 << k;
    let mut tc = 0;
    while tc < m {
        let tw = tile_blocks.min(m - tc);
        let tb = tw * 16;
        let ctr = (filled + tc) as u64;
        fold::stretch(aes, leaves, tw, ctr, src, scratch);
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
        // ū_b = u_b ⊕ u (the shared monochrome choices for these columns).
        let ch = &choices[(filled + tc) * 16..(filled + tc) * 16 + tb];
        let dst = &mut us_row[tc * 16..tc * 16 + tb];
        dst.copy_from_slice(&u_tile[..tb]);
        fold::xor_into(dst, ch);
        tc += tw;
    }
}

#[derive(Debug)]
struct Queued {
    count: usize,
    sender: Sender<RCOTReceiverOutput<bool, Block>>,
}

/// SoftSpoken receiver.
#[derive(Debug, Default)]
pub struct Receiver<T: state::State = state::Initialized> {
    config: ReceiverConfig,
    alloc: usize,
    transfer_id: TransferId,
    queue: VecDeque<Queued>,
    state: T,
}

impl<T> Receiver<T>
where
    T: state::State,
{
    /// Returns the Receiver's configuration
    pub fn config(&self) -> &ReceiverConfig {
        &self.config
    }
}

impl Receiver {
    /// Creates a new receiver.
    pub fn new(config: ReceiverConfig) -> Self {
        Receiver {
            config,
            // SSP extra OTs are sacrificed to the consistency check.
            alloc: SSP,
            transfer_id: TransferId::default(),
            queue: VecDeque::default(),
            state: state::Initialized {},
        }
    }

    /// Loads the base-OT seed pairs, advancing to the `corrections` step.
    pub fn setup(self, seeds: [[Block; 2]; CSP]) -> Receiver<state::Setup> {
        Receiver {
            config: self.config,
            alloc: self.alloc,
            transfer_id: self.transfer_id,
            queue: self.queue,
            state: state::Setup {
                seeds: seeds
                    .iter()
                    .map(|[a, b]| [a.to_bytes(), b.to_bytes()])
                    .collect(),
            },
        }
    }
}

impl Receiver<state::Setup> {
    /// Builds the trees and emits the one-time [`Corrections`] for the sender,
    /// advancing to the extension phase.
    pub fn corrections(self) -> (Receiver<state::Extension>, Corrections) {
        let k = self.config.k();
        let n_blocks = self.config.n_blocks();
        let q = self.config.leaves();

        let mut rng = rand::rng();
        // Fresh per-instance key for the MMO leaf stretch.
        let s: [u8; 16] = rng.random();
        let hasher = FixedKeyAes::new(s);

        let seeds = self.state.seeds;
        let aes = ggm::expander();
        let mut leaf_seeds = vec![[0u8; 16]; n_blocks * q];
        let mut corrections = vec![[0u8; 16]; 2 * CSP];
        let mut parents = vec![[0u8; 16]; q / 2];
        for b in 0..n_blocks {
            let root: [u8; 16] = rng.random();
            ggm::build_full(
                &aes,
                root,
                &seeds[b * k..b * k + k],
                &mut leaf_seeds[b * q..(b + 1) * q],
                &mut corrections[2 * k * b..2 * k * (b + 1)],
                &mut parents,
            );
        }

        let receiver = Receiver {
            config: self.config,
            alloc: self.alloc,
            transfer_id: self.transfer_id,
            queue: self.queue,
            state: state::Extension {
                hasher,
                leaf_seeds,
                mac: Vec::default(),
                choices: Vec::default(),
                total_rb: 0,
                filled: 0,
                out_total: 0,
                consumed: 0,
                extended: false,
            },
        };

        (receiver, Corrections { corrections, s })
    }
}

impl Receiver<state::Extension> {
    /// Returns `true` if the receiver wants to extend.
    pub fn wants_extend(&self) -> bool {
        self.alloc != 0 && !self.state.extended
    }

    /// Returns `true` if the receiver wants to run the consistency check.
    pub fn wants_check(&self) -> bool {
        self.alloc == 0 && !self.state.extended && !self.state.mac.is_empty()
    }

    /// Produces one extension batch as an [`Extend`] message.
    pub fn extend(&mut self) -> Result<Extend, ReceiverError> {
        if self.state.extended {
            return Err(ReceiverError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        let k = self.config.k();
        let n_blocks = self.config.n_blocks();
        let q = self.config.leaves();

        // Round up to a multiple of SSP (the rows sacrificed to the check).
        let count = self.config.batch_size().min(self.alloc).next_multiple_of(SSP);
        let rb = count / 8;
        let m = count / CSP; // blocks per row this batch

        // First extend: size the single MAC matrix from the (now final) demand.
        // The GGM trees were already built in the `corrections` transition.
        if self.state.mac.is_empty() {
            let total = self.alloc.next_multiple_of(SSP);
            let total_rb = total / 8;
            self.state.total_rb = total_rb;
            self.state.mac = vec![0u8; CSP * total_rb];
            self.state.choices = vec![0u8; total_rb];
        }

        let total_rb = self.state.total_rb;
        let filled = self.state.filled;
        let tile_blocks = (TILE_TARGET_BLOCKS / q).max(1).min(m);

        // The shared monochrome choice vector for this batch's OTs.
        rand::rng().fill_bytes(&mut self.state.choices[filled * 16..filled * 16 + rb]);

        let mut us = vec![0u8; n_blocks * rb];

        let hasher = &self.state.hasher;
        let leaf_seeds = &self.state.leaf_seeds;
        let mac = &mut self.state.mac;
        let choices = &self.state.choices;
        let make_buf = || {
            (
                vec![[0u8; 16]; q * tile_blocks],
                vec![[0u8; 16]; q * tile_blocks],
                vec![0u8; tile_blocks * 16],
            )
        };

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                leaf_seeds
                    .par_chunks(q)
                    .zip(mac.par_chunks_mut(k * total_rb))
                    .zip(us.par_chunks_mut(rb))
                    .for_each_init(make_buf, |(src, scratch, u_tile), ((leaves, slab), us_row)| {
                        fold_block(
                            hasher, leaves, slab, us_row, src, scratch, u_tile, k, total_rb, filled,
                            m, tile_blocks, choices,
                        );
                    });
            } else {
                let (mut src, mut scratch, mut u_tile) = make_buf();
                leaf_seeds
                    .chunks(q)
                    .zip(mac.chunks_mut(k * total_rb))
                    .zip(us.chunks_mut(rb))
                    .for_each(|((leaves, slab), us_row)| {
                        fold_block(
                            hasher, leaves, slab, us_row, &mut src, &mut scratch, &mut u_tile, k,
                            total_rb, filled, m, tile_blocks, choices,
                        );
                    });
            }
        }

        self.state.filled = filled + m;
        self.alloc = self.alloc.saturating_sub(count);

        Ok(Extend { count, us })
    }

    /// Computes the consistency [`Check`] over all extended OTs.
    pub fn check(&mut self, chi_seed: Block) -> Result<Check, ReceiverError> {
        if !self.wants_check() {
            return Err(ReceiverError::InvalidState(
                "receiver not ready to check".to_string(),
            ));
        }

        let total_rb = self.state.total_rb;

        let (check_t, check_x) =
            check::check_fold(chi_seed, &self.state.mac, total_rb, Some(&self.state.choices));
        let check_x = check_x.expect("choices were provided");

        // Transpose the matrix in place: it becomes the per-OT MACs. The last
        // SSP OTs are sacrificed to the check.
        matrix_transpose::transpose_bits(&mut self.state.mac, CSP).expect("matrix is rectangular");
        self.state.out_total = total_rb * 8 - SSP;
        self.state.extended = true;

        // Resolve any queued transfers.
        for Queued { count, sender } in mem::take(&mut self.queue) {
            let (choices, msgs) = self.take_output(count);
            sender.send(RCOTReceiverOutput {
                id: self.transfer_id.next(),
                choices,
                msgs,
            });
        }

        Ok(Check {
            x: check_x,
            t: check_t,
        })
    }

    /// Consumes `count` checked OTs from the transposed matrix.
    fn take_output(&mut self, count: usize) -> (Vec<bool>, Vec<Block>) {
        let start = self.state.consumed;
        let choices = (start..start + count)
            .map(|i| (self.state.choices[i / 8] >> (i % 8)) & 1 == 1)
            .collect();
        let msgs = <[Block]>::ref_from_bytes(&self.state.mac[start * 16..(start + count) * 16])
            .expect("multiple of Block size")
            .to_vec();
        self.state.consumed += count;
        (choices, msgs)
    }
}

impl RCOTReceiver<bool, Block> for Receiver<state::Initialized> {
    type Error = ReceiverError;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        0
    }

    fn try_recv_rcot(
        &mut self,
        _count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        Err(ReceiverError::InvalidState(
            "receiver has not been set up yet".to_string(),
        ))
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.queue.push_back(Queued { count, sender });

        Ok(recv)
    }
}

impl RCOTReceiver<bool, Block> for Receiver<state::Extension> {
    type Error = ReceiverError;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.state.extended {
            return Err(ReceiverError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        self.state.out_total - self.state.consumed
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        if self.available() < count {
            return Err(ReceiverError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            });
        }

        let (choices, msgs) = self.take_output(count);

        Ok(RCOTReceiverOutput {
            id: self.transfer_id.next(),
            choices,
            msgs,
        })
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.available() >= count {
            let output = self.try_recv_rcot(count)?;
            let (sender, recv) = new_output();
            sender.send(output);

            Ok(recv)
        } else if !self.state.extended {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            Ok(recv)
        } else {
            Err(ReceiverError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            })
        }
    }
}

/// The receiver's state.
pub mod state {
    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Setup {}
        impl Sealed for super::Extension {}
    }

    /// The receiver's state.
    pub trait State: sealed::Sealed {}

    /// The receiver's initial state.
    #[derive(Default)]
    pub struct Initialized {}

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The receiver's state after base OT, holding the seed pairs until the
    /// tree corrections are sent.
    pub struct Setup {
        /// Base-OT seed pairs.
        pub(super) seeds: Vec<[[u8; 16]; 2]>,
    }

    impl State for Setup {}

    opaque_debug::implement!(Setup);

    /// The receiver's state after the setup phase.
    pub struct Extension {
        /// Per-instance MMO hash for the leaf stretch (keyed by the seed `s`).
        pub(super) hasher: mpz_core::aes::FixedKeyAes,
        /// GGM leaf seeds (`n_blocks * 2^k`), stretched with the MMO PRG.
        pub(super) leaf_seeds: Vec<[u8; 16]>,
        /// The single MAC matrix: `CSP × total_rb` bytes, row-major. Filled
        /// column-by-column during extension, then transposed in place to the
        /// per-OT MACs at the consistency check.
        pub(super) mac: Vec<u8>,
        /// Packed monochrome choices, `total_rb` bytes (one bit per OT).
        pub(super) choices: Vec<u8>,
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
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
