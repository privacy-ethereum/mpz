//! Ferret sender.
use std::collections::VecDeque;

use mpz_core::{
    lpn::{LpnEncoder, LpnParameters},
    Block,
};

use crate::{
    ferret::{error::SenderError, LpnType},
    RCOTSenderOutput, TransferId,
};

use super::msgs::LpnMatrixSeed;

/// Ferret sender.
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
    /// See step 1 and 2 in Figure 9.
    ///
    /// # Arguments
    ///
    /// * `delta` - The sender's global secret.
    /// * `lpn_parameters` - The lpn parameters.
    /// * `lpn_type` - The lpn type.
    /// * `seed` - The seed received from receiver to generate lpn matrix.
    /// * `v` - The vector received from the COT ideal functionality.
    pub fn setup(
        self,
        delta: Block,
        lpn_parameters: LpnParameters,
        lpn_type: LpnType,
        seed: LpnMatrixSeed,
        v: &[Block],
    ) -> Result<Sender<state::Extension>, SenderError> {
        if v.len() != lpn_parameters.k {
            return Err(SenderError(
                "the length of v should be equal to k".to_string(),
            ));
        }
        let LpnMatrixSeed { seed } = seed;
        let lpn_encoder = LpnEncoder::<10>::new(seed, lpn_parameters.k as u32);

        Ok(Sender {
            state: state::Extension {
                delta,
                counter: 0,
                lpn_parameters,
                lpn_type,
                lpn_encoder,
                v: v.to_vec(),
                id: TransferId::default(),
                msgs_buffer: VecDeque::new(),
            },
        })
    }
}

impl Sender<state::Extension> {
    /// Returns the current transfer id.
    pub fn id(&self) -> TransferId {
        self.state.id
    }

    /// Returns the number of remaining COTs.
    pub fn remaining(&self) -> usize {
        self.state.msgs_buffer.len()
    }

    /// Returns the delta correlation.
    pub fn delta(&self) -> Block {
        self.state.delta
    }

    /// Outputs the information for MPCOT.
    ///
    /// See step 3 and 4.
    #[inline]
    pub fn get_mpcot_query(&self) -> (u32, u32) {
        (
            self.state.lpn_parameters.t as u32,
            self.state.lpn_parameters.n as u32,
        )
    }

    /// Performs the Ferret extension.
    /// Outputs exactly l = n-t COTs.
    ///
    /// See step 5 and 6.
    ///
    /// # Arguments.
    ///
    /// * `s` - The vector received from the MPCOT protocol.
    pub fn extend(&mut self, s: Vec<Block>) -> Result<(), SenderError> {
        if s.len() != self.state.lpn_parameters.n {
            return Err(SenderError("the length of s should be n".to_string()));
        }

        self.state.id.next();

        // Compute y = A * v + s
        let mut y = s;
        self.state.lpn_encoder.compute(&mut y, &self.state.v);

        let y_ = y.split_off(self.state.lpn_parameters.k);

        // Update v to y[0..k]
        self.state.v = y;

        // Update counter
        self.state.counter += 1;
        self.state.msgs_buffer.extend(y_);

        Ok(())
    }

    /// Consumes `count` COTs.
    pub fn consume(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, SenderError> {
        if count > self.state.msgs_buffer.len() {
            return Err(SenderError(format!(
                "insufficient OTs: {} < {count}",
                self.state.msgs_buffer.len()
            )));
        }

        let msgs = self.state.msgs_buffer.drain(0..count).collect();

        Ok(RCOTSenderOutput {
            id: self.state.id.next(),
            msgs,
        })
    }
}

/// The sender's state.
pub mod state {
    use crate::TransferId;

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
    /// In this state the sender performs Ferret extension (potentially multiple times).
    pub struct Extension {
        /// Sender's global secret.
        #[allow(dead_code)]
        pub(super) delta: Block,
        /// Current Ferret counter.
        pub(super) counter: usize,

        /// Lpn type.
        #[allow(dead_code)]
        pub(super) lpn_type: LpnType,
        /// Lpn parameters.
        pub(super) lpn_parameters: LpnParameters,
        /// Lpn encoder.
        pub(super) lpn_encoder: LpnEncoder<10>,

        /// Sender's COT message in the setup phase.
        pub(super) v: Vec<Block>,

        /// Transfer ID.
        pub(crate) id: TransferId,
        /// COT messages buffer.
        pub(super) msgs_buffer: VecDeque<Block>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
