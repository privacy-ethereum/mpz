//! MPCOT receiver for general indices.
use std::sync::Arc;

use crate::ferret::{
    cuckoo::{find_pos, hash_to_index, Bucket, CuckooHash, Item},
    mpcot::error::ReceiverError,
    CUCKOO_HASH_NUM,
};
use mpz_core::{aes::AesEncryptor, prg::Prg, Block};
use rand_core::SeedableRng;

use super::msgs::HashSeed;

/// MPCOT receiver.
#[derive(Debug, Default)]
pub struct Receiver<T: state::State = state::Initialized> {
    state: T,
}

impl Receiver {
    /// Creates a new Receiver.
    pub fn new() -> Self {
        Receiver {
            state: state::Initialized::default(),
        }
    }

    /// Completes the setup phase for PreExtend.
    ///
    /// See step 1 in Figure 6.
    ///
    /// # Argument
    ///
    /// * `hash_seed` - Random seed to generate hashes, will be sent to the sender.
    pub fn setup(self, hash_seed: Block) -> (Receiver<state::PreExtension>, HashSeed) {
        let mut prg = Prg::from_seed(hash_seed);
        let hashes = std::array::from_fn(|_| AesEncryptor::new(prg.random_block()));
        let recv = Receiver {
            state: state::PreExtension {
                counter: 0,
                hashes: Arc::new(hashes),
            },
        };

        let seed = HashSeed { seed: hash_seed };

        (recv, seed)
    }
}

impl Receiver<state::PreExtension> {
    /// Performs the hash procedure in MPCOT extension.
    /// Outputs the length of each bucket plus 1.
    ///
    /// See Step 1 to Step 4 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `alphas` - The queried indices.
    /// * `n` - The total number of indices.
    #[allow(clippy::type_complexity)]
    pub fn pre_extend(
        self,
        alphas: &[u32],
        n: u32,
    ) -> Result<(Receiver<state::Extension>, Vec<(usize, u32)>), ReceiverError> {
        if alphas.len() as u32 > n {
            return Err(ReceiverError::InvalidInput(
                "length of alphas should not exceed n".to_string(),
            ));
        }
        let cuckoo = CuckooHash::new(self.state.hashes.clone());

        // Inserts all the alpha's.
        let table = cuckoo.insert(alphas)?;

        let m = table.len();

        let bucket = Bucket::new(self.state.hashes.clone(), m);

        // Generates the buckets.
        let buckets = bucket.insert(n);

        // Generates queries for SPCOT.
        // See Step 4 in Figure 7.
        let mut p = vec![];
        let mut buckets_length = vec![];
        for (alpha, bin) in table.iter().zip(buckets.iter()) {
            // pad to power of 2.
            let power_of_two = (bin.len() + 1)
                .checked_next_power_of_two()
                .expect("bucket length should be less than usize::MAX / 2 - 1");

            let power = power_of_two.ilog2() as usize;

            if let Some(x) = alpha {
                let pos = find_pos(bin, x)?;
                p.push((power, pos as u32));
            } else {
                p.push((power, bin.len() as u32));
            }

            buckets_length.push(power_of_two);
        }

        let receiver = Receiver {
            state: state::Extension {
                counter: self.state.counter,
                m,
                n,
                hashes: self.state.hashes.clone(),
                buckets,
                buckets_length,
            },
        };

        Ok((receiver, p))
    }
}
impl Receiver<state::Extension> {
    /// Performs MPCOT extension.
    ///
    /// See Step 5 in Figure 7.
    ///
    /// # Arguments
    ///
    /// * `rt` - The vector received from SPCOT protocol on multiple queries.
    pub fn extend(
        self,
        rt: &[Vec<Block>],
    ) -> Result<(Receiver<state::PreExtension>, Vec<Block>), ReceiverError> {
        if rt.len() != self.state.m {
            return Err(ReceiverError::InvalidInput(
                "the length rt should be m".to_string(),
            ));
        }

        if rt
            .iter()
            .zip(self.state.buckets_length.iter())
            .any(|(s, b)| s.len() != *b)
        {
            return Err(ReceiverError::InvalidInput(
                "the length of st[i] should be self.state.buckets_length".to_string(),
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

                *x ^= rt[bucket_index][pos];
            }
        }

        let receiver = Receiver {
            state: state::PreExtension {
                counter: self.state.counter + 1,
                hashes: self.state.hashes,
            },
        };

        Ok((receiver, res))
    }
}
/// The receiver's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}

        impl Sealed for super::Initialized {}
        impl Sealed for super::PreExtension {}
        impl Sealed for super::Extension {}
    }

    /// The receiver's state.
    pub trait State: sealed::Sealed {}

    /// The receiver's initial state.
    #[derive(Default)]
    pub struct Initialized {}

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The receiver's state before extending.
    ///
    /// In this state the receiver performs pre extension in MPCOT (potentially multiple times).
    pub struct PreExtension {
        /// Current MPCOT counter
        pub(super) counter: usize,
        /// The hashes to generate Cuckoo hash table.
        pub(super) hashes: Arc<[AesEncryptor; CUCKOO_HASH_NUM]>,
    }

    impl State for PreExtension {}

    opaque_debug::implement!(PreExtension);
    /// The receiver's state of extension.
    ///
    /// In this state the receiver performs MPCOT extension (potentially multiple times).
    pub struct Extension {
        /// Current MPCOT counter
        pub(super) counter: usize,
        /// Current length of Cuckoo hash table, will possibly be changed in each extension.
        pub(super) m: usize,
        /// The total number of indices in the current extension.
        pub(super) n: u32,
        /// The hashes to generate Cuckoo hash table.
        pub(super) hashes: Arc<[AesEncryptor; CUCKOO_HASH_NUM]>,
        /// The buckets contains all the hash values, will be cleared after each extension.
        pub(super) buckets: Vec<Vec<Item>>,
        /// The padded buckets length (power of 2).
        pub(super) buckets_length: Vec<usize>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
