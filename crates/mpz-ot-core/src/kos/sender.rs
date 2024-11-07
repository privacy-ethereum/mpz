use std::{collections::VecDeque, mem};

use crate::{
    kos::{Check, Extend, SenderConfig, SenderError, CSP, SSP},
    rcot::{RCOTSender, RCOTSenderOutput},
    TransferId,
};

use mpz_common::future::{new_output, MaybeDone, Sender as OutputSender};
use mpz_core::{prg::Prg, Block};

use rand::{Rng as _, SeedableRng};
use rand_core::RngCore;

cfg_if::cfg_if! {
    if #[cfg(feature = "rayon")] {
        use itybity::ToParallelBits;
        use rayon::prelude::*;
    } else {
        use itybity::ToBits;
    }
}

#[derive(Debug)]
struct Queued {
    count: usize,
    sender: OutputSender<RCOTSenderOutput<Block>>,
}

/// KOS15 sender.
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
    /// Creates a new Sender
    ///
    /// # Arguments
    ///
    /// * `config` - Sender's configuration.
    /// * `delta` - Global COT correlation.
    pub fn new(config: SenderConfig, delta: Block) -> Self {
        Sender {
            config,
            // We need to extend CSP + SSP OTs for the consistency check.
            // Right now we only support one extension, so we just alloc
            // them here.
            alloc: CSP + SSP,
            transfer_id: TransferId::default(),
            queue: VecDeque::default(),
            delta,
            state: state::Initialized::default(),
        }
    }

    /// Complete the setup phase of the protocol.
    ///
    /// # Arguments
    ///
    /// * `seeds` - The rng seeds chosen during base OT
    pub fn setup(self, seeds: [Block; CSP]) -> Sender<state::Extension> {
        Sender {
            config: self.config,
            alloc: self.alloc,
            transfer_id: self.transfer_id,
            queue: self.queue,
            delta: self.delta,
            state: state::Extension {
                rngs: seeds.into_iter().map(|seed| Prg::from_seed(seed)).collect(),
                keys: Vec::default(),
                extended: false,
                unchecked_qs: Vec::default(),
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
        self.alloc == 0 && !self.state.unchecked_qs.is_empty()
    }

    /// Perform the IKNP OT extension.
    ///
    /// # Arguments
    ///
    /// * `extend` - Extend message from the receiver.
    pub fn extend(&mut self, extend: Extend) -> Result<(), SenderError> {
        if self.state.extended {
            return Err(SenderError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        let Extend { count, us } = extend;

        let expected_count = self.config.batch_size().min(self.alloc);
        // round up count to a multiple of 64
        let expected_count = (expected_count + 63) & !63;
        if count != expected_count {
            return Err(SenderError::CountMismatch {
                expected: expected_count,
                actual: count,
            });
        }

        const NROWS: usize = CSP;
        let row_width = count / 8;

        let mut qs = vec![0u8; NROWS * row_width];
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = self.delta
                    .par_iter_lsb0()
                    .zip(self.state.rngs.par_iter_mut())
                    .zip(qs.par_chunks_exact_mut(row_width))
                    .zip(us.par_chunks_exact(row_width));
            } else {
                let iter = self.delta
                    .iter_lsb0()
                    .zip(self.state.rngs.iter_mut())
                    .zip(qs.chunks_exact_mut(row_width))
                    .zip(us.chunks_exact(row_width));
            }
        }

        // Figure 3, step 4.
        let zero = vec![0u8; row_width];
        iter.for_each(|(((b, rng), q), u)| {
            // Reuse `q` to avoid memory allocation for tⁱ_∆ᵢ
            rng.fill_bytes(q);
            // If `b` (i.e. ∆ᵢ) is true, xor `u` into `q`, otherwise xor 0 into `q`
            // (constant time).
            let u = if b { u } else { &zero };
            q.iter_mut().zip(u).for_each(|(q, u)| *q ^= u);
        });

        // Figure 3, step 5.
        matrix_transpose::transpose_bits(&mut qs, NROWS).expect("matrix is rectangular");

        self.state
            .unchecked_qs
            .extend(qs.chunks_exact(NROWS / 8).map(|q| {
                let q: Block = q.try_into().unwrap();
                q
            }));
        self.alloc = self.alloc.saturating_sub(count);

        Ok(())
    }

    /// Performs the correlation check for all outstanding OTS.
    ///
    /// See section 3.1 of the paper for more details.
    ///
    /// # ⚠️ Warning ⚠️
    ///
    /// The provided seed must be unbiased! It should be generated using a
    /// secure coin-toss protocol **after** the receiver has sent their
    /// extension message, ie after they have already committed to their
    /// choice vectors.
    ///
    /// # Arguments
    ///
    /// * `chi_seed` - The seed used to generate the consistency check weights.
    /// * `receiver_check` - The receiver's consistency check message.
    pub fn check(&mut self, chi_seed: Block, receiver_check: Check) -> Result<(), SenderError> {
        if !self.wants_check() {
            return Err(SenderError::InvalidState("not ready to check".to_string()));
        }

        // Make sure we have enough sacrificial OTs to perform the consistency check.
        if self.state.unchecked_qs.len() < CSP + SSP {
            return Err(SenderError::InsufficientSetup {
                expected: CSP + SSP,
                actual: self.state.unchecked_qs.len(),
            });
        }

        let mut rng = Prg::from_seed(chi_seed);

        let mut unchecked_qs = std::mem::take(&mut self.state.unchecked_qs);

        // Figure 7, "Check correlation", point 1.
        // Sample random weights for the consistency check.
        let chis = (0..unchecked_qs.len())
            .map(|_| rng.gen())
            .collect::<Vec<_>>();

        // Figure 7, "Check correlation", point 3.
        // Compute the random linear combinations.
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let check = unchecked_qs.par_iter()
                    .zip(chis)
                    .map(|(q, chi)| q.clmul(chi))
                    .reduce(
                        || (Block::ZERO, Block::ZERO),
                        |(_a, _b), (a, b)| (a ^ _a, b ^ _b),
                    );
            } else {
                let check = unchecked_qs.iter()
                    .zip(chis)
                    .map(|(q, chi)| q.clmul(chi))
                    .reduce(
                        |(_a, _b), (a, b)| (a ^ _a, b ^ _b),
                    ).unwrap();
            }
        }

        let Check { x, t0, t1 } = receiver_check;
        let tmp = x.clmul(self.delta);
        let check = (check.0 ^ tmp.0, check.1 ^ tmp.1);

        // The Receiver is malicious.
        //
        // Call the police!
        if check != (t0, t1) {
            return Err(SenderError::ConsistencyCheckFailed);
        }

        // Strip off the rows sacrificed for the consistency check.
        let nrows = unchecked_qs.len() - (CSP + SSP);
        unchecked_qs.truncate(nrows);

        self.state.keys.extend_from_slice(&unchecked_qs);
        self.state.extended = true;

        // Resolve any queued transfers.
        if !self.queue.is_empty() {
            let mut i = 0;
            for Queued { count, sender } in mem::take(&mut self.queue) {
                let keys = self.state.keys[i..i + count].to_vec();
                i += count;
                sender.send(RCOTSenderOutput {
                    id: self.transfer_id.next(),
                    keys,
                });
            }

            self.state.keys.drain(..i);
        }

        Ok(())
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
        return Err(SenderError::InvalidState(
            "sender has not been setup yet".to_string(),
        ));
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.queue.push_back(Queued { count, sender });

        return Ok(recv);
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
        self.state.keys.len()
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

        let keys = self.state.keys.drain(..count).collect();

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

            return Ok(recv);
        } else if !self.state.extended {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            return Ok(recv);
        } else {
            return Err(SenderError::InsufficientSetup {
                expected: count,
                actual: self.available(),
            });
        }
    }
}

/// The sender's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Extension {}
    }

    /// The sender's state.
    pub trait State: sealed::Sealed {}

    /// The sender's initial state.
    #[derive(Default)]
    pub struct Initialized {}

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The sender's state after the setup phase.
    ///
    /// In this state the sender performs OT extension (potentially multiple
    /// times). Also in this state the sender responds to OT requests.
    pub struct Extension {
        /// Receiver's rngs seeded from seeds obliviously received from base OT
        pub(super) rngs: Vec<Prg>,
        /// Whether extension has occurred yet
        ///
        /// This is to prevent the receiver from extending twice
        pub(super) extended: bool,
        /// Sender's unchecked qs
        pub(super) unchecked_qs: Vec<Block>,
        /// Sender's keys
        pub(super) keys: Vec<Block>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
