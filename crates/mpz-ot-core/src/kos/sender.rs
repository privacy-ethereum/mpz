use crate::{
    kos::{
        extension_matrix_size,
        msgs::{Check, Ciphertexts, Extend, SenderPayload},
        Aes128Ctr, Rng, RngSeed, SenderConfig, SenderError, CSP, SSP,
    },
    msgs::Derandomize,
};

use cipher::{KeyIvInit, StreamCipher};
use itybity::ToBits;
use mpz_core::{aes::FIXED_KEY_AES, Block};

use rand::{Rng as _, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;

cfg_if::cfg_if! {
    if #[cfg(feature = "rayon")] {
        use itybity::ToParallelBits;
        use rayon::prelude::*;
    } else {
        use itybity::ToBits;
    }
}

/// KOS15 sender.
#[derive(Debug, Default)]
pub struct Sender<T: state::State = state::Initialized> {
    config: SenderConfig,
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

impl Sender {
    /// Creates a new Sender
    ///
    /// # Arguments
    ///
    /// * `config` - The Sender's configuration
    pub fn new(config: SenderConfig) -> Self {
        Sender {
            config,
            state: state::Initialized::default(),
        }
    }

    /// Complete the setup phase of the protocol.
    ///
    /// # Arguments
    ///
    /// * `delta` - The sender's base OT choice bits
    /// * `seeds` - The rng seeds chosen during base OT
    pub fn setup(self, delta: Block, seeds: [Block; CSP]) -> Sender<state::Extension> {
        let rngs = seeds
            .iter()
            .map(|seed| {
                // Stretch the Block-sized seed to a 32-byte seed.
                let mut seed_ = RngSeed::default();
                seed_
                    .iter_mut()
                    .zip(seed.to_bytes().into_iter().cycle())
                    .for_each(|(s, c)| *s = c);
                Rng::from_seed(seed_)
            })
            .collect();

        Sender {
            config: self.config,
            state: state::Extension {
                delta,
                rngs,
                keys: Vec::default(),
                transfer_id: 0,
                counter: 0,
                extended: false,
                unchecked_qs: Vec::default(),
            },
        }
    }
}

impl Sender<state::Extension> {
    /// The number of remaining OTs which can be consumed.
    pub fn remaining(&self) -> usize {
        self.state.keys.len()
    }

    /// Perform the IKNP OT extension.
    ///
    /// The provided count _must_ be a multiple of 64, otherwise an error will be returned.
    ///
    /// # Sacrificial OTs
    ///
    /// Performing the consistency check sacrifices 256 OTs, so be sure to extend enough to
    /// compensate for this.
    ///
    /// # Streaming
    ///
    /// Extension can be performed in a streaming fashion by processing an extension in batches via
    /// multiple calls to this method.
    ///
    /// The freshly extended OTs are not available until after the consistency check has been
    /// performed. See [`Sender::check`].
    ///
    /// # Arguments
    ///
    /// * `count` - The number of additional OTs to extend (must be a multiple of 64).
    /// * `extend` - The receiver's setup message.
    pub fn extend(&mut self, count: usize, extend: Extend) -> Result<(), SenderError> {
        if self.state.extended {
            return Err(SenderError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        if count % 64 != 0 {
            return Err(SenderError::InvalidCount(count));
        }

        const NROWS: usize = CSP;
        let row_width = count / 8;

        let Extend { us } = extend;

        if us.len() != extension_matrix_size(count) {
            return Err(SenderError::InvalidExtend);
        }

        let mut qs = vec![0u8; NROWS * row_width];
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = self.state.delta
                    .par_iter_lsb0()
                    .zip(self.state.rngs.par_iter_mut())
                    .zip(qs.par_chunks_exact_mut(row_width))
                    .zip(us.par_chunks_exact(row_width));
            } else {
                let iter = self.state.delta
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
            // If `b` (i.e. ∆ᵢ) is true, xor `u` into `q`, otherwise xor 0 into `q` (constant time).
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

        Ok(())
    }

    /// Performs the correlation check for all outstanding OTS.
    ///
    /// See section 3.1 of the paper for more details.
    ///
    /// # Sacrificial OTs
    ///
    /// Performing this check sacrifices 256 OTs for the consistency check, so be sure to
    /// extend enough OTs to compensate for this.
    ///
    /// # ⚠️ Warning ⚠️
    ///
    /// The provided seed must be unbiased! It should be generated using a secure
    /// coin-toss protocol **after** the receiver has sent their extension message, ie
    /// after they have already committed to their choice vectors.
    ///
    /// # Arguments
    ///
    /// * `chi_seed` - The seed used to generate the consistency check weights.
    /// * `receiver_check` - The receiver's consistency check message.
    pub fn check(&mut self, chi_seed: Block, receiver_check: Check) -> Result<(), SenderError> {
        // Make sure we have enough sacrificial OTs to perform the consistency check.
        if self.state.unchecked_qs.len() < CSP + SSP {
            return Err(SenderError::InsufficientSetup(
                CSP + SSP,
                self.state.unchecked_qs.len(),
            ));
        }

        let mut seed = RngSeed::default();
        seed.iter_mut()
            .zip(chi_seed.to_bytes().into_iter().cycle())
            .for_each(|(s, c)| *s = c);

        let mut rng = Rng::from_seed(seed);

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
        let tmp = x.clmul(self.state.delta);
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

        // Figure 7, "Randomization"
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = unchecked_qs.into_par_iter().enumerate();
            } else {
                let iter = unchecked_qs.into_iter().enumerate();
            }
        }

        let cipher = &(*FIXED_KEY_AES);
        let keys = iter
            .map(|(j, q)| {
                let j = Block::new(((self.state.counter + j) as u128).to_be_bytes());

                let k0 = cipher.tccr(j, q);
                let k1 = cipher.tccr(j, q ^ self.state.delta);

                [k0, k1]
            })
            .collect::<Vec<_>>();

        self.state.counter += keys.len();
        self.state.keys.extend(keys);
        self.state.extended = true;

        Ok(())
    }

    /// Reserves a set of keys which can be used to encrypt a payload later.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of keys to reserve.
    pub fn keys(&mut self, count: usize) -> Result<SenderKeys, SenderError> {
        if count > self.state.keys.len() {
            return Err(SenderError::InsufficientSetup(count, self.state.keys.len()));
        }

        let id = self.state.transfer_id;
        self.state.transfer_id += 1;

        Ok(SenderKeys {
            id,
            keys: self.state.keys.drain(..count).collect(),
            derandomize: None,
        })
    }
}

/// KOS sender's keys for a single transfer.
///
/// Returned by the [`Sender::keys`] method, used in cases where the sender
/// wishes to reserve a set of keys for use later, while still being able to process
/// other payloads.
pub struct SenderKeys {
    /// Transfer ID
    id: u32,
    /// Encryption keys
    keys: Vec<[Block; 2]>,
    /// Derandomization
    derandomize: Option<Derandomize>,
}

impl SenderKeys {
    /// Returns the transfer ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Applies Beaver derandomization to correct the receiver's choices made during extension.
    pub fn derandomize(&mut self, derandomize: Derandomize) -> Result<(), SenderError> {
        if derandomize.id != self.id {
            return Err(SenderError::IdMismatch(self.id, derandomize.id));
        }

        if derandomize.count as usize != self.keys.len() {
            return Err(SenderError::CountMismatch(
                self.keys.len(),
                derandomize.count as usize,
            ));
        }

        self.derandomize = Some(derandomize);

        Ok(())
    }

    /// Encrypts the provided messages using the keys.
    ///
    /// # Arguments
    ///
    /// * `msgs` - The messages to encrypt
    pub fn encrypt_blocks(self, msgs: &[[Block; 2]]) -> Result<SenderPayload, SenderError> {
        if msgs.len() != self.keys.len() {
            return Err(SenderError::InsufficientSetup(msgs.len(), self.keys.len()));
        }

        // If we have derandomization, use it to correct the receiver's choices, else we use
        // default
        let flip = self
            .derandomize
            .map(|x| x.flip)
            .unwrap_or_else(|| vec![0; self.keys.len() / 8 + 1]);

        // Encrypt the chosen messages using the generated keys from ROT.
        let ciphertexts = self
            .keys
            .into_iter()
            .zip(msgs)
            .zip(flip.iter_lsb0())
            .flat_map(|(([k0, k1], [m0, m1]), flip)| {
                // Use Beaver derandomization to correct the receiver's choices
                // from the extension phase.
                if flip {
                    [k1 ^ *m0, k0 ^ *m1]
                } else {
                    [k0 ^ *m0, k1 ^ *m1]
                }
            })
            .collect();

        Ok(SenderPayload {
            id: self.id,
            ciphertexts: Ciphertexts::Blocks { ciphertexts },
        })
    }

    /// Encrypts the provided messages using the keys.
    ///
    /// # Arguments
    ///
    /// * `msgs` - The messages to encrypt
    pub fn encrypt_bytes<const N: usize>(
        self,
        msgs: &[[[u8; N]; 2]],
    ) -> Result<SenderPayload, SenderError> {
        if msgs.len() != self.keys.len() {
            return Err(SenderError::InsufficientSetup(msgs.len(), self.keys.len()));
        }

        // Generate a random IV which is used for all messages.
        // This is safe because every message is encrypted with a different key.
        let iv: [u8; 16] = rand::thread_rng().gen();

        // If we have derandomization, use it to correct the receiver's choices, else we use
        // default
        let flip = self
            .derandomize
            .map(|x| x.flip)
            .unwrap_or_else(|| vec![0; self.keys.len() / 8 + 1]);

        // Encrypt the chosen messages using the generated keys from ROT.
        let ciphertexts = self
            .keys
            .into_iter()
            .zip(msgs)
            .zip(flip.iter_lsb0())
            .flat_map(|(([k0, k1], [m0, m1]), flip)| {
                // Initialize AES-CTR with the keys from ROT.
                let mut e0 = Aes128Ctr::new(&k0.into(), &iv.into());
                let mut e1 = Aes128Ctr::new(&k1.into(), &iv.into());

                let mut m0 = *m0;
                let mut m1 = *m1;

                // Use Beaver derandomization to correct the receiver's choices
                // from the extension phase.
                if flip {
                    e1.apply_keystream(&mut m0);
                    e0.apply_keystream(&mut m1);
                } else {
                    e0.apply_keystream(&mut m0);
                    e1.apply_keystream(&mut m1);
                }

                [m0, m1]
            })
            .flatten()
            .collect();

        Ok(SenderPayload {
            id: self.id,
            ciphertexts: Ciphertexts::Bytes {
                ciphertexts,
                iv: iv.to_vec(),
                length: N as u32,
            },
        })
    }

    /// Returns the keys
    pub fn take_keys(self) -> Vec<[Block; 2]> {
        self.keys
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
    /// In this state the sender performs OT extension (potentially multiple times). Also in this
    /// state the sender responds to OT requests.
    pub struct Extension {
        /// Sender's base OT choices
        pub(super) delta: Block,
        /// Receiver's rngs seeded from seeds obliviously received from base OT
        pub(super) rngs: Vec<ChaCha20Rng>,
        /// Sender's keys
        pub(super) keys: Vec<[Block; 2]>,

        /// Current transfer id
        pub(super) transfer_id: u32,
        /// Current OT counter
        pub(super) counter: usize,

        /// Whether extension has occurred yet
        ///
        /// This is to prevent the receiver from extending twice
        pub(super) extended: bool,

        /// Sender's unchecked qs
        pub(super) unchecked_qs: Vec<Block>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
