use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    kos::{
        error::ReceiverVerifyError,
        msgs::{Check, Ciphertexts, Extend, SenderPayload},
        Aes128Ctr, ReceiverConfig, ReceiverError, Rng, RngSeed, CSP, SSP,
    },
    msgs::Derandomize,
};

use itybity::{FromBitIterator, IntoBits, ToBits};
use mpz_core::{aes::FIXED_KEY_AES, Block};

use blake3::Hasher;
use cipher::{KeyIvInit, StreamCipher};
use rand::{thread_rng, Rng as _, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;

#[cfg(feature = "rayon")]
use rayon::prelude::*;

#[derive(Debug, Default)]
struct Tape {
    records: HashMap<u32, PayloadRecordNoDelta>,
}

/// KOS15 receiver.
#[derive(Debug, Default)]
pub struct Receiver<T: state::State = state::Initialized> {
    config: ReceiverConfig,
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
    /// Creates a new Receiver
    ///
    /// # Arguments
    ///
    /// * `config` - The Receiver's configuration
    pub fn new(config: ReceiverConfig) -> Self {
        let tape = if config.sender_commit() {
            Some(Default::default())
        } else {
            None
        };

        Receiver {
            config,
            state: state::Initialized { tape },
        }
    }

    /// Complete the setup phase of the protocol.
    ///
    /// # Arguments
    ///
    /// * `seeds` - The receiver's rng seeds
    pub fn setup(self, seeds: [[Block; 2]; CSP]) -> Receiver<state::Extension> {
        let rngs = seeds
            .iter()
            .map(|seeds| {
                seeds.map(|seed| {
                    // Stretch the Block-sized seed to a 32-byte seed.
                    let mut seed_ = RngSeed::default();
                    seed_
                        .iter_mut()
                        .zip(seed.to_bytes().into_iter().cycle())
                        .for_each(|(s, c)| *s = c);
                    Rng::from_seed(seed_)
                })
            })
            .collect();

        Receiver {
            config: self.config,
            state: state::Extension {
                rngs,
                ts: Vec::default(),
                keys: Vec::default(),
                choices: Vec::default(),
                index: 0,
                transfer_id: 0,
                extended: false,
                unchecked_ts: Vec::default(),
                unchecked_choices: Vec::default(),
                tape: self.state.tape,
            },
        }
    }
}

impl Receiver<state::Extension> {
    /// Returns the current transfer id.
    pub fn current_transfer_id(&self) -> u32 {
        self.state.transfer_id
    }

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
    /// Performing the consistency check sacrifices 256 OTs, so be sure to
    /// extend enough OTs to compensate for this.
    ///
    /// # Streaming
    ///
    /// Extension can be performed in a streaming fashion by calling this method multiple times, sending
    /// the `Extend` messages to the sender in-between calls.
    ///
    /// The freshly extended OTs are not available until after the consistency check has been
    /// performed. See [`Receiver::check`].
    ///
    /// # Arguments
    ///
    /// * `count` - The number of OTs to extend (must be a multiple of 64).
    pub fn extend(&mut self, count: usize) -> Result<Extend, ReceiverError> {
        if self.state.extended {
            return Err(ReceiverError::InvalidState(
                "extending more than once is currently disabled".to_string(),
            ));
        }

        if count % 64 != 0 {
            return Err(ReceiverError::InvalidCount(count));
        }

        const NROWS: usize = CSP;
        let row_width = count / 8;

        let mut rng = thread_rng();
        // x₁,...,xₗ bits in Figure 3, step 1.
        let choices = (0..row_width)
            .flat_map(|_| rng.gen::<u8>().into_iter_lsb0())
            .collect::<Vec<_>>();

        // 𝐱ⁱ in Figure 3. Note that it is the same for all i = 1,...,k.
        let choice_vector = Vec::<u8>::from_lsb0_iter(choices.iter().copied());

        // 𝐭₀ⁱ in Figure 3.
        let mut ts = vec![0u8; NROWS * row_width];
        let mut us = vec![0u8; NROWS * row_width];
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = self.state.rngs
                    .par_iter_mut()
                    .zip(ts.par_chunks_exact_mut(row_width))
                    .zip(us.par_chunks_exact_mut(row_width));
            } else {
                let iter = self.state.rngs
                    .iter_mut()
                    .zip(ts.chunks_exact_mut(row_width))
                    .zip(us.chunks_exact_mut(row_width));
            }
        }

        iter.for_each(|((rngs, t_0), u)| {
            // Figure 3, step 2.
            rngs[0].fill_bytes(t_0);
            // reuse u to avoid memory allocation for 𝐭₁ⁱ
            rngs[1].fill_bytes(u);

            // Figure 3, step 3.
            // Computing `u = t_0 + t_1 + x`.
            u.iter_mut()
                .zip(t_0)
                .zip(&choice_vector)
                .for_each(|((u, t_0), x)| {
                    *u ^= *t_0 ^ x;
                });
        });

        matrix_transpose::transpose_bits(&mut ts, NROWS).expect("matrix is rectangular");

        self.state.unchecked_ts.extend(
            ts.chunks_exact(NROWS / 8)
                .map(|t| Block::try_from(t).unwrap()),
        );
        self.state.unchecked_choices.extend(choices);

        Ok(Extend { us })
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
    /// coin-toss protocol **after** the receiver has sent their setup message, ie
    /// after they have already committed to their choice vectors.
    ///
    /// # Arguments
    ///
    /// * `chi_seed` - The seed used to generate the consistency check weights.
    pub fn check(&mut self, chi_seed: Block) -> Result<Check, ReceiverError> {
        // Make sure we have enough sacrificial OTs to perform the consistency check.
        if self.state.unchecked_ts.len() < CSP + SSP {
            return Err(ReceiverError::InsufficientSetup(
                CSP + SSP,
                self.state.unchecked_ts.len(),
            ));
        }

        let mut seed = RngSeed::default();
        seed.iter_mut()
            .zip(chi_seed.to_bytes().into_iter().cycle())
            .for_each(|(s, c)| *s = c);

        let mut rng = Rng::from_seed(seed);

        let mut unchecked_ts = std::mem::take(&mut self.state.unchecked_ts);
        let mut unchecked_choices = std::mem::take(&mut self.state.unchecked_choices);

        // Figure 7, "Check correlation", point 1.
        // Sample random weights for the consistency check.
        let chis = (0..unchecked_ts.len())
            .map(|_| Block::random(&mut rng))
            .collect::<Vec<_>>();

        // Figure 7, "Check correlation", point 2.
        // Compute the random linear combinations.
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let (x, t0, t1) = unchecked_choices.par_iter()
                    .zip(&unchecked_ts)
                    .zip(chis)
                    .map(|((c, t), chi)| {
                        let x = if *c { chi } else { Block::ZERO };
                        let (t0, t1) = t.clmul(chi);
                        (x, t0, t1)
                    })
                    .reduce(
                        || (Block::ZERO, Block::ZERO, Block::ZERO),
                        |(_x, _t0, _t1), (x, t0, t1)| {
                            (_x ^ x, _t0 ^ t0, _t1 ^ t1)
                        },
                    );
            } else {
                let (x, t0, t1) = unchecked_choices.iter()
                    .zip(&unchecked_ts)
                    .zip(chis)
                    .map(|((c, t), chi)| {
                        let x = if *c { chi } else { Block::ZERO };
                        let (t0, t1) = t.clmul(chi);
                        (x, t0, t1)
                    })
                    .reduce(|(_x, _t0, _t1), (x, t0, t1)| {
                        (_x ^ x, _t0 ^ t0, _t1 ^ t1)
                    }).unwrap();
            }
        }

        // Strip off the rows sacrificed for the consistency check.
        let nrows = unchecked_ts.len() - (CSP + SSP);
        unchecked_ts.truncate(nrows);
        unchecked_choices.truncate(nrows);

        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")] {
                let iter = unchecked_ts.par_iter().enumerate();
            } else {
                let iter = unchecked_ts.iter().enumerate();
            }
        }

        let cipher = &(*FIXED_KEY_AES);
        let keys = iter
            .map(|(j, t)| {
                let j = Block::from(((self.state.index + j) as u128).to_be_bytes());
                cipher.tccr(j, *t)
            })
            .collect::<Vec<_>>();

        self.state.index += keys.len();

        // Add to existing keys.
        self.state.keys.extend(keys);
        self.state.choices.extend(unchecked_choices);

        // If we're recording, we track `ts` too
        if self.state.tape.is_some() {
            self.state.ts.extend(unchecked_ts);
        }

        // Disable any further extensions.
        self.state.extended = true;

        Ok(Check { x, t0, t1 })
    }

    /// Returns receiver's keys for the given number of OTs.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of keys to take.
    pub fn keys(&mut self, count: usize) -> Result<ReceiverKeys, ReceiverError> {
        if count > self.state.keys.len() {
            return Err(ReceiverError::InsufficientSetup(
                count,
                self.state.keys.len(),
            ));
        }

        let id = self.state.transfer_id;
        let index = self.state.index - self.state.keys.len();

        self.state.transfer_id += 1;

        Ok(ReceiverKeys {
            id,
            index,
            keys: self.state.keys.drain(..count).collect(),
            choices: self.state.choices.drain(..count).collect(),
            ts: if self.state.tape.is_some() {
                Some(self.state.ts.drain(..count).collect())
            } else {
                None
            },
            tape: self.state.tape.clone(),
        })
    }

    /// Enters the verification state for verifiable OT.
    ///
    /// # ⚠️ Warning ⚠️
    ///
    /// The authenticity of `delta` must be established outside the context of this function. This
    /// can be achieved using verifiable base OT.
    ///
    /// # Arguments
    ///
    /// * `delta` - The sender's base OT choice bits.
    pub fn start_verification(
        mut self,
        delta: Block,
    ) -> Result<Receiver<state::Verify>, ReceiverError> {
        let Some(tape) = self.state.tape.take() else {
            return Err(ReceiverVerifyError::TapeNotRecorded)?;
        };

        Ok(Receiver {
            config: self.config,
            state: state::Verify { tape, delta },
        })
    }
}

impl Receiver<state::Verify> {
    /// Returns the [`PayloadRecord`] for the given transfer id if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the record does not exist.
    ///
    /// # Arguments
    ///
    /// * `id` - The transfer id
    pub fn remove_record(&self, id: u32) -> Result<PayloadRecord, ReceiverError> {
        let PayloadRecordNoDelta {
            index,
            choices,
            ts,
            keys,
            ciphertext_digest,
        } = self
            .state
            .tape
            .lock()
            .unwrap()
            .records
            .remove(&id)
            .ok_or(ReceiverVerifyError::InvalidTransferId(id))
            .map_err(ReceiverError::from)?;

        Ok(PayloadRecord {
            index,
            choices,
            ts,
            keys,
            delta: self.state.delta,
            ciphertext_digest,
        })
    }
}

/// KOS receiver's keys for a single transfer.
///
/// Returned by the [`Receiver::keys`] method, used in cases where the receiver
/// wishes to reserve a set of keys for a transfer, but hasn't yet received the
/// payload.
pub struct ReceiverKeys {
    /// Transfer ID
    id: u32,
    /// Start index of the OTs
    index: usize,
    /// Decryption keys
    keys: Vec<Block>,
    /// The Receiver's choices. If derandomization is performed, these are the overwritten
    /// with the derandomized choices.
    choices: Vec<bool>,

    /// Receiver `ts`
    ts: Option<Vec<Block>>,
    /// Receiver tape
    tape: Option<Arc<Mutex<Tape>>>,
}

opaque_debug::implement!(ReceiverKeys);

impl ReceiverKeys {
    /// Returns the transfer ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Derandomizes the receiver's choices.
    pub fn derandomize(&mut self, choices: &[bool]) -> Result<Derandomize, ReceiverError> {
        if choices.len() != self.choices.len() {
            return Err(ReceiverError::CountMismatch(
                self.choices.len(),
                choices.len(),
            ));
        }

        let derandomize = Derandomize {
            id: self.id,
            count: self.choices.len() as u32,
            flip: Vec::<u8>::from_lsb0_iter(
                self.choices
                    .iter()
                    .zip(choices)
                    .map(|(setup_choice, new_choice)| setup_choice ^ new_choice),
            ),
        };

        self.choices.copy_from_slice(choices);

        Ok(derandomize)
    }

    /// Decrypts the sender's payload.
    pub fn decrypt_blocks(mut self, payload: SenderPayload) -> Result<Vec<Block>, ReceiverError> {
        let SenderPayload { id, ciphertexts } = payload;

        let Ciphertexts::Blocks { ciphertexts } = ciphertexts else {
            return Err(ReceiverError::InvalidPayload(
                "expected block ciphertexts".to_string(),
            ));
        };

        if id != self.id {
            return Err(ReceiverError::IdMismatch(self.id, id));
        }

        if ciphertexts.len() / 2 != self.keys.len() {
            return Err(ReceiverError::CountMismatch(
                self.keys.len(),
                ciphertexts.len() / 2,
            ));
        }

        if let Some(tape) = self.tape.take() {
            let ts = self.ts.take().expect("ts set if tape is set");

            let mut hasher = Hasher::default();
            ciphertexts.iter().for_each(|ct| {
                hasher.update(&ct.to_bytes());
            });

            tape.lock().unwrap().records.insert(
                id,
                PayloadRecordNoDelta {
                    index: self.index,
                    choices: Vec::from_lsb0_iter(self.choices.iter().copied()),
                    ts,
                    keys: self.keys.clone(),
                    ciphertext_digest: hasher.finalize().into(),
                },
            );
        }

        Ok(self
            .keys
            .into_iter()
            .zip(self.choices)
            .zip(ciphertexts.chunks(2))
            .map(|((key, c), ct)| if c { key ^ ct[1] } else { key ^ ct[0] })
            .collect())
    }

    /// Decrypts the sender's payload.
    ///
    /// # Verifiable OT
    ///
    /// Verifiable OT with KOS does not currently support byte payloads, so no record of this payload
    /// will be recorded.
    pub fn decrypt_bytes<const N: usize>(
        self,
        payload: SenderPayload,
    ) -> Result<Vec<[u8; N]>, ReceiverError> {
        let SenderPayload { id, ciphertexts } = payload;

        let Ciphertexts::Bytes {
            ciphertexts,
            iv,
            length,
        } = ciphertexts
        else {
            return Err(ReceiverError::InvalidPayload(
                "expected byte ciphertexts".to_string(),
            ));
        };

        if id != self.id {
            return Err(ReceiverError::IdMismatch(self.id, id));
        }

        let length = length as usize;
        if length != N {
            return Err(ReceiverError::InvalidPayload(format!(
                "invalid message length: expected {}, got {}",
                N, length
            )));
        }

        if ciphertexts.len() / (2 * length) != self.keys.len() {
            return Err(ReceiverError::CountMismatch(
                self.keys.len(),
                ciphertexts.len() / (2 * length),
            ));
        }

        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| ReceiverError::InvalidPayload("invalid iv length".to_string()))?;

        Ok(self
            .keys
            .into_iter()
            .zip(self.choices)
            .zip(ciphertexts.chunks(2 * N))
            .map(|((key, c), ct)| {
                // Initialize AES-CTR with the key from ROT.
                let mut e = Aes128Ctr::new(&key.into(), &iv.into());

                let mut msg = [0u8; N];
                if c {
                    msg.copy_from_slice(&ct[N..])
                } else {
                    msg.copy_from_slice(&ct[..N])
                };

                e.apply_keystream(&mut msg);

                msg
            })
            .collect())
    }

    /// Returns the choices and the keys
    pub fn take_choices_and_keys(self) -> (Vec<bool>, Vec<Block>) {
        (self.choices, self.keys)
    }
}

struct PayloadRecordNoDelta {
    /// The starting index for the corresponding OTs. This is used to compute the
    /// "tweak" for the randomization.
    index: usize,
    /// The receiver's choices for the transfer.
    choices: Vec<u8>,
    ts: Vec<Block>,
    keys: Vec<Block>,
    ciphertext_digest: [u8; 32],
}

opaque_debug::implement!(PayloadRecordNoDelta);

/// A record of a transfer's payload.
pub struct PayloadRecord {
    /// The starting index for the corresponding OTs. This is used to compute the
    /// "tweak" for the randomization.
    index: usize,
    /// The receiver's choices for the transfer.
    choices: Vec<u8>,
    ts: Vec<Block>,
    keys: Vec<Block>,
    /// The sender's base OT choice bits.
    delta: Block,
    ciphertext_digest: [u8; 32],
}

opaque_debug::implement!(PayloadRecord);

impl PayloadRecord {
    /// Checks the purported messages against the record
    ///
    /// # Arguments
    ///
    /// * `purported_msgs` - The purported messages sent by the sender.
    pub fn verify(self, purported_msgs: &[[Block; 2]]) -> Result<(), ReceiverError> {
        let PayloadRecord {
            index: counter,
            choices,
            ts,
            keys,
            delta,
            ciphertext_digest,
        } = self;

        // Here we compute the complementary key to the one used earlier in the protocol.
        //
        // From this, we encrypt the purported messages and check that the ciphertext digests match.
        let cipher = &(*FIXED_KEY_AES);
        let mut hasher = Hasher::default();
        for (j, (((c, t), key), msgs)) in choices
            .iter_lsb0()
            .zip(ts)
            .zip(keys)
            .zip(purported_msgs)
            .enumerate()
        {
            let j = Block::new(((counter + j) as u128).to_be_bytes());
            let key_ = cipher.tccr(j, t ^ delta);

            let (ct0, ct1) = if c {
                (msgs[0] ^ key_, msgs[1] ^ key)
            } else {
                (msgs[0] ^ key, msgs[1] ^ key_)
            };

            hasher.update(&ct0.to_bytes());
            hasher.update(&ct1.to_bytes());
        }

        let digest: [u8; 32] = hasher.finalize().into();

        if ciphertext_digest != digest {
            return Err(ReceiverVerifyError::InconsistentPayload)?;
        }

        Ok(())
    }
}

/// The receiver's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::Extension {}
        impl Sealed for super::Verify {}
    }

    /// The receiver's state.
    pub trait State: sealed::Sealed {}

    /// The receiver's initial state.
    #[derive(Default)]
    pub struct Initialized {
        /// Protocol tape
        pub(super) tape: Option<Arc<Mutex<Tape>>>,
    }

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The receiver's state after the setup phase.
    ///
    /// In this state the receiver performs OT extension (potentially multiple times). Also in this
    /// state the receiver sends OT requests.
    pub struct Extension {
        /// Receiver's rngs
        pub(super) rngs: Vec<[ChaCha20Rng; 2]>,
        /// Receiver's ts
        pub(super) ts: Vec<Block>,
        /// Receiver's keys
        pub(super) keys: Vec<Block>,
        /// Receiver's random choices
        pub(super) choices: Vec<bool>,
        /// Current OT index
        pub(super) index: usize,
        /// Current transfer id
        pub(super) transfer_id: u32,

        /// Whether extension has occurred yet
        ///
        /// This is to prevent the receiver from extending twice
        pub(super) extended: bool,

        /// Receiver's unchecked ts
        pub(super) unchecked_ts: Vec<Block>,
        /// Receiver's unchecked choices
        pub(super) unchecked_choices: Vec<bool>,

        /// Protocol tape
        pub(super) tape: Option<Arc<Mutex<Tape>>>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);

    /// The receiver's state after receiving the sender's base OT choice bits, a.k.a delta.
    pub struct Verify {
        /// Protocol tape
        pub(super) tape: Arc<Mutex<Tape>>,
        /// The sender's base OT choice bits.
        pub(super) delta: Block,
    }

    impl State for Verify {}

    opaque_debug::implement!(Verify);
}
