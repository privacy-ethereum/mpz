//! MPCOT sender for regular indices. Regular indices means the indices are evenly distributed.

use mpz_core::Block;

use crate::ferret::mpcot::error::SenderError;

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

    /// Completes the setup phase of the protocol.
    ///
    /// # Argument.
    ///
    /// * `delta` - The sender's global secret.
    pub fn setup(self, delta: Block) -> Sender<state::PreExtension> {
        Sender {
            state: state::PreExtension { delta, counter: 0 },
        }
    }
}

impl Sender<state::PreExtension> {
    /// Performs the prepare procedure in MPCOT extension.
    /// Outputs the information for SPCOT.
    ///
    /// # Arguments.
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

        // The range of each interval.
        let k = n.div_ceil(t);

        let queries_length = if n % t == 0 {
            vec![k as usize; t as usize]
        } else {
            let mut tmp = vec![k as usize; (t - 1) as usize];
            tmp.push((n % k) as usize);
            if tmp.iter().sum::<usize>() != n as usize {
                return Err(SenderError::InvalidInput(
                    "the input parameters (t,n) are not regular".to_string(),
                ));
            } else {
                tmp
            }
        };

        let mut queries_depth = Vec::with_capacity(queries_length.len());

        for len in queries_length.iter() {
            // pad `len`` to power of 2.
            let power = len
                .checked_next_power_of_two()
                .expect("len should be less than usize::MAX / 2 - 1")
                .ilog2() as usize;
            queries_depth.push(power);
        }

        let sender = Sender {
            state: state::Extension {
                delta: self.state.delta,
                counter: self.state.counter,
                n,
                queries_length,
                queries_depth: queries_depth.clone(),
            },
        };

        Ok((sender, queries_depth))
    }
}

impl Sender<state::Extension> {
    /// Performs MPCOT extension.
    ///
    /// # Arguments.
    ///
    /// * `st` - The vector received from SPCOT protocol on multiple queries.
    pub fn extend(
        self,
        st: &[Vec<Block>],
    ) -> Result<(Sender<state::PreExtension>, Vec<Block>), SenderError> {
        if st
            .iter()
            .zip(self.state.queries_depth.iter())
            .any(|(blks, m)| blks.len() != 1 << m)
        {
            return Err(SenderError::InvalidInput(
                "the length of st[i] should be 2^self.state.queries_depth[i]".to_string(),
            ));
        }
        let mut res: Vec<Block> = Vec::with_capacity(self.state.n as usize);

        for (blks, pos) in st.iter().zip(self.state.queries_length.iter()) {
            res.extend(&blks[..*pos]);
        }

        let sender = Sender {
            state: state::PreExtension {
                delta: self.state.delta,
                counter: self.state.counter + 1,
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
    }

    impl State for PreExtension {}
    opaque_debug::implement!(PreExtension);

    /// The sender's state after the setup phase.
    ///
    /// In this state the sender performs MPCOT extension (potentially multiple times).
    pub struct Extension {
        /// Sender's global secret.
        pub(super) delta: Block,
        /// Current MPCOT counter
        pub(super) counter: usize,
        /// The total number of indices in the current extension.
        pub(super) n: u32,
        /// Current queries from sender, will possibly be changed in each extension.
        pub(super) queries_length: Vec<usize>,
        /// The depth of queries.
        pub(super) queries_depth: Vec<usize>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
