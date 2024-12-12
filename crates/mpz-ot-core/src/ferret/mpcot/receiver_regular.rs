//! MPCOT receiver for regular indices. Regular indices means the indices are evenly distributed.

use mpz_core::Block;

use crate::ferret::mpcot::error::ReceiverError;

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

    /// Completes the setup phase of the protocol.
    pub fn setup(self) -> Receiver<state::PreExtension> {
        Receiver {
            state: state::PreExtension { counter: 0 },
        }
    }
}
impl Receiver<state::PreExtension> {
    /// Performs the prepare procedure in MPCOT extension.
    /// Outputs the indices for SPCOT.
    ///
    /// # Arguments.
    ///
    /// * `alphas` - The queried indices.
    /// * `n` - The total number of indices.
    #[allow(clippy::type_complexity)]
    pub fn pre_extend(
        self,
        alphas: &[u32],
        n: u32,
    ) -> Result<(Receiver<state::Extension>, Vec<(usize, u32)>), ReceiverError> {
        let t = alphas.len() as u32;
        if t > n {
            return Err(ReceiverError::InvalidInput(
                "the length of alpha should not exceed n".to_string(),
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
                return Err(ReceiverError::InvalidInput(
                    "the input parameters (t,n) are not regular".to_string(),
                ));
            } else {
                tmp
            }
        };

        let mut queries_depth = Vec::with_capacity(queries_length.len());
        for len in queries_length.iter() {
            // pad `len` to power of 2.
            let power = len
                .checked_next_power_of_two()
                .expect("len should be less than usize::MAX / 2 - 1")
                .ilog2() as usize;

            queries_depth.push(power);
        }

        if !alphas
            .iter()
            .enumerate()
            .all(|(i, &alpha)| (i as u32) * k <= alpha && alpha < ((i + 1) as u32) * k)
        {
            return Err(ReceiverError::InvalidInput(
                "the input position is not regular".to_string(),
            ));
        }

        let res: Vec<(usize, u32)> = queries_depth
            .iter()
            .zip(alphas.iter())
            .map(|(&d, &alpha)| (d, alpha % k))
            .collect();

        let receiver = Receiver {
            state: state::Extension {
                counter: self.state.counter,
                n,
                queries_length,
                queries_depth,
            },
        };

        Ok((receiver, res))
    }
}

impl Receiver<state::Extension> {
    /// Performs MPCOT extension.
    ///
    /// # Arguments.
    ///
    /// * `rt` - The vector received from SPCOT protocol on multiple queries.
    pub fn extend(
        self,
        rt: &[Vec<Block>],
    ) -> Result<(Receiver<state::PreExtension>, Vec<Block>), ReceiverError> {
        if rt
            .iter()
            .zip(self.state.queries_depth.iter())
            .any(|(blks, m)| blks.len() != 1 << m)
        {
            return Err(ReceiverError::InvalidInput(
                "the length of rt[i] should be 2^self.state.queries_depth[i]".to_string(),
            ));
        }

        let mut res: Vec<Block> = Vec::with_capacity(self.state.n as usize);

        for (blks, pos) in rt.iter().zip(self.state.queries_length.iter()) {
            res.extend(&blks[..*pos]);
        }

        let receiver = Receiver {
            state: state::PreExtension {
                counter: self.state.counter + 1,
            },
        };

        Ok((receiver, res))
    }
}
/// The receiver's state.
pub mod state {

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
    }

    impl State for PreExtension {}

    opaque_debug::implement!(PreExtension);

    /// The receiver's state after the setup phase.
    ///
    /// In this state the receiver performs MPCOT extension (potentially multiple times).
    pub struct Extension {
        /// Current MPCOT counter
        #[allow(dead_code)]
        pub(super) counter: usize,
        /// The total number of indices in the current extension.
        pub(super) n: u32,
        /// Current queries length.
        pub(super) queries_length: Vec<usize>,
        /// The depth of queries.
        pub(super) queries_depth: Vec<usize>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
