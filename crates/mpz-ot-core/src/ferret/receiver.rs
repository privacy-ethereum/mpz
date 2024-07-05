//! Ferret receiver
use std::collections::VecDeque;

use mpz_core::{
    lpn::{LpnEncoder, LpnParameters},
    Block,
};

use crate::{
    ferret::{error::ReceiverError, LpnType},
    RCOTReceiverOutput, TransferId,
};

use super::msgs::LpnMatrixSeed;

/// Ferret receiver.
#[derive(Debug, Default)]
pub struct Receiver<T: state::State = state::Initialized> {
    state: T,
}

impl Receiver {
    /// Create a new Receiver.
    pub fn new() -> Self {
        Receiver {
            state: state::Initialized::default(),
        }
    }

    /// Completes the setup phase of the protocol.
    ///
    /// See step 1 and 2 in Figure 9.
    ///
    /// # Arguments
    ///
    /// * `lpn_parameters` - The lpn parameters.
    /// * `seed` - The seed to generate lpn matrix.
    /// * `lpn_type` - The lpn type.
    /// * `u` - The bits received from the COT ideal functionality.
    /// * `w` - The vector received from the COT ideal functionality.
    pub fn setup(
        self,
        lpn_parameters: LpnParameters,
        lpn_type: LpnType,
        seed: Block,
        u: &[bool],
        w: &[Block],
    ) -> Result<(Receiver<state::Extension>, LpnMatrixSeed), ReceiverError> {
        if u.len() != lpn_parameters.k || w.len() != lpn_parameters.k {
            return Err(ReceiverError(
                "the length of u and w should be k".to_string(),
            ));
        }

        let lpn_encoder = LpnEncoder::<10>::new(seed, lpn_parameters.k as u32);

        Ok((
            Receiver {
                state: state::Extension {
                    counter: 0,
                    lpn_parameters,
                    lpn_encoder,
                    lpn_type,
                    u: u.to_vec(),
                    w: w.to_vec(),
                    e: Vec::default(),
                    id: TransferId::default(),
                    choices_buffer: VecDeque::new(),
                    msgs_buffer: VecDeque::new(),
                },
            },
            LpnMatrixSeed { seed },
        ))
    }
}

impl Receiver<state::Extension> {
    /// Returns the current transfer id.
    pub fn id(&self) -> TransferId {
        self.state.id
    }

    /// Returns the number of remaining COTs.
    pub fn remaining(&self) -> usize {
        self.state.choices_buffer.len()
    }

    /// The prepare precedure of extension, sample error vectors and outputs information for MPCOT.
    /// See step 3 and 4.
    pub fn get_mpcot_query(&mut self) -> (Vec<u32>, usize) {
        match self.state.lpn_type {
            LpnType::Uniform => {
                self.state.e = self.state.lpn_parameters.sample_uniform_error_vector();
            }

            LpnType::Regular => {
                self.state.e = self.state.lpn_parameters.sample_regular_error_vector();
            }
        }
        let mut alphas = Vec::with_capacity(self.state.lpn_parameters.t);
        for (i, x) in self.state.e.iter().enumerate() {
            if *x != Block::ZERO {
                alphas.push(i as u32);
            }
        }
        (alphas, self.state.lpn_parameters.n)
    }

    /// Performs the Ferret extension.
    /// Outputs exactly l = n - t COTs.
    ///
    /// See step 5 and 6.
    ///
    /// # Arguments.
    ///
    /// * `r` - The vector received from the MPCOT protocol.
    pub fn extend(&mut self, r: Vec<Block>) -> Result<(), ReceiverError> {
        if r.len() != self.state.lpn_parameters.n {
            return Err(ReceiverError("the length of r should be n".to_string()));
        }

        self.state.id.next();

        // Compute z = A * w + r.
        let mut z = r;
        self.state.lpn_encoder.compute(&mut z, &self.state.w);

        // Compute x = A * u + e.
        let u_block = self
            .state
            .u
            .iter()
            .map(|x| if *x { Block::ONE } else { Block::ZERO })
            .collect::<Vec<Block>>();
        let mut x = self.state.e.clone();
        self.state.lpn_encoder.compute(&mut x, &u_block);

        let mut x = x.iter().map(|a| a.lsb() == 1).collect::<Vec<bool>>();

        let x_ = x.split_off(self.state.lpn_parameters.k);
        let z_ = z.split_off(self.state.lpn_parameters.k);

        // Update u, w
        self.state.u = x;
        self.state.w = z;

        // Update counter
        self.state.counter += 1;

        self.state.choices_buffer.extend(x_);
        self.state.msgs_buffer.extend(z_);

        Ok(())
    }

    /// Consumes `count` COTs.
    pub fn consume(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, ReceiverError> {
        if count > self.state.choices_buffer.len() {
            return Err(ReceiverError(format!(
                "insufficient OTs: {} < {count}",
                self.state.choices_buffer.len()
            )));
        }

        let choices = self.state.choices_buffer.drain(0..count).collect();
        let msgs = self.state.msgs_buffer.drain(0..count).collect();

        Ok(RCOTReceiverOutput {
            id: self.state.id.next(),
            choices,
            msgs,
        })
    }
}

/// The receiver's state.
pub mod state {
    use super::*;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Initialized {}
        impl Sealed for super::Extension {}
    }

    /// The receiver's state.
    pub trait State: sealed::Sealed {}

    /// The receiver's initial state.
    #[derive(Default)]
    pub struct Initialized {}

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The receiver's state after the setup phase.
    ///
    /// In this state the sender performs Ferret extension (potentially multiple times).
    pub struct Extension {
        /// Current Ferret counter.
        pub(super) counter: usize,

        /// Lpn parameters.
        pub(super) lpn_parameters: LpnParameters,
        /// Lpn encoder.
        pub(super) lpn_encoder: LpnEncoder<10>,
        /// Lpn type.
        pub(super) lpn_type: LpnType,

        /// Receiver's COT messages in the setup phase.
        pub(super) u: Vec<bool>,
        pub(super) w: Vec<Block>,

        /// Receiver's lpn error vector.
        pub(super) e: Vec<Block>,

        /// TransferID
        pub(super) id: TransferId,
        /// Extended OTs buffers.
        pub(super) choices_buffer: VecDeque<bool>,
        pub(super) msgs_buffer: VecDeque<Block>,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
