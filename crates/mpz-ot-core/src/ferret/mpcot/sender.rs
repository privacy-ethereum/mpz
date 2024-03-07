//! MPCOT sender for general indices.
use std::sync::Arc;

use crate::ferret::{
    cuckoo::{compute_table_length, find_pos, hash_to_index, Bucket, Item},
    mpcot::error::SenderError,
    CUCKOO_HASH_NUM,
};
use mpz_core::{aes::AesEncryptor, prg::Prg, Block};
use rand_core::SeedableRng;

use super::msgs::HashSeed;

/// MPCOT sender.
#[derive(Debug, Default)]
pub struct Sender<T: state::State = state::Initialized> {
    state: T,
}

impl Sender {
    /// Creates a new Sender.
    pub fn new() -> Self {
        Sender {
            state: state::Initialized::default(),
        }
    }

    /// Completes the setup phase for PreExtend.
    ///
    /// # Arguments.
    ///
    /// * `delta` - The sender's global secret.
    /// * `hash_seed` - The seed for Cuckoo hash sent by the receiver.
    pub fn setup(self, delta: Block, hash_seed: HashSeed) -> Sender<state::PreExtension> {
        let HashSeed { seed: hash_seed } = hash_seed;
        let mut prg = Prg::from_seed(hash_seed);
        let hashes = std::array::from_fn(|_| AesEncryptor::new(prg.random_block()));
        Sender {
            state: state::PreExtension {
                delta,
                counter: 0,
                hashes: Arc::new(hashes),
            },
        }
    }
}

impl Sender<state::PreExtension> {
    /// Performs the hash procedure in MPCOT extension.
    /// Outputs the length of each bucket plus 1.
    ///
    /// See Step 1 to Step 4 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `t` - The number of queried indices.
    /// * `n` - The total number of indices.
    pub fn pre_extend(
        self,
        t: u32,
        n: u32,
    ) -> Result<(Sender<state::Extension>, Vec<usize>), SenderError> {
        if t > n {
            return Err(SenderError::InvalidInput(
                "t should not exceed n".to_string(),
            ));
        }

        // Compute m = 1.5 * t.
        let m = compute_table_length(t);

        let bucket = Bucket::new(self.state.hashes.clone(), m);

        // Generates the buckets.
        let buckets = bucket.insert(n);

        // First pad (length + 1) to a pow of 2, then computes `log(length + 1)` of each bucket.
        let mut bs = vec![];
        let mut buckets_length = vec![];
        for bin in buckets.iter() {
            let power_of_two = (bin.len() + 1)
                .checked_next_power_of_two()
                .expect("bucket length should be less than usize::MAX / 2 - 1");
            bs.push(power_of_two.ilog2() as usize);
            buckets_length.push(power_of_two);
        }

        let sender = Sender {
            state: state::Extension {
                delta: self.state.delta,
                counter: self.state.counter,
                m,
                n,
                hashes: self.state.hashes,
                buckets,
                buckets_length,
            },
        };

        Ok((sender, bs))
    }
}

impl Sender<state::Extension> {
    /// Performs MPCOT extension.
    ///
    /// See Step 5 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `st` - The vector received from SPCOT protocol on multiple queries.
    pub fn extend(
        self,
        st: &[Vec<Block>],
    ) -> Result<(Sender<state::PreExtension>, Vec<Block>), SenderError> {
        if st.len() != self.state.m {
            return Err(SenderError::InvalidInput(
                "the length st should be m".to_string(),
            ));
        }

        if st
            .iter()
            .zip(self.state.buckets_length.iter())
            .any(|(s, b)| s.len() != *b)
        {
            return Err(SenderError::InvalidInput(
                "the length of st[i] should be self.state.buckets_length[i]".to_string(),
            ));
        }
        let mut res = vec![Block::ZERO; self.state.n as usize];
        for (value, x) in res.iter_mut().enumerate() {
            for tau in 0..CUCKOO_HASH_NUM {
                // Computes the index of `value`.
                let bucket_index =
                    hash_to_index(&self.state.hashes[tau], self.state.m, value as u32);
                let pos = find_pos(
                    &self.state.buckets[bucket_index],
                    &Item {
                        value: value as u32,
                        hash_index: tau,
                    },
                )?;

                *x ^= st[bucket_index][pos];
            }
        }

        let sender = Sender {
            state: state::PreExtension {
                delta: self.state.delta,
                counter: self.state.counter + 1,
                hashes: self.state.hashes,
            },
        };

        Ok((sender, res))
    }
}

/// The sender's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::PreExtension {}
        impl Sealed for super::Extension {}
    }

    /// The sender's state.
    pub trait State: sealed::Sealed {}

    /// The sender's initial state.
    #[derive(Default)]
    pub struct Initialized {}

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The sender's state before extending.
    ///
    /// In this state the sender performs pre extension in MPCOT (potentially multiple times).
    pub struct PreExtension {
        /// Sender's global secret.
        pub(super) delta: Block,
        /// Current MPCOT counter
        pub(super) counter: usize,
        /// The hashes to generate Cuckoo hash table.
        pub(super) hashes: Arc<[AesEncryptor; CUCKOO_HASH_NUM]>,
    }

    impl State for PreExtension {}
    opaque_debug::implement!(PreExtension);

    /// The sender's state of extension.
    ///
    /// In this state the sender performs MPCOT extension (potentially multiple times).
    pub struct Extension {
        /// Sender's global secret.
        pub(super) delta: Block,
        /// Current MPCOT counter
        pub(super) counter: usize,

        /// Current length of Cuckoo hash table, will possibly be changed in each extension.
        pub(super) m: usize,
        /// The total number of indices in the current extension.
        pub(super) n: u32,
        /// The hashes to generate Cuckoo hash table.
        pub(super) hashes: Arc<[AesEncryptor; CUCKOO_HASH_NUM]>,
        /// The buckets contains all the hash values.
        pub(super) buckets: Vec<Vec<Item>>,
        /// The padded buckets length (power of 2).
        pub(super) buckets_length: Vec<usize>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
