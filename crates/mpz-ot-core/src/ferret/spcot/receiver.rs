//! SPCOT receiver
use crate::ferret::{spcot::error::ReceiverError, CSP};
use itybity::ToBits;
use mpz_core::{
    aes::FIXED_KEY_AES, ggm_tree::GgmTree, hash::Hash, prg::Prg, serialize::CanonicalSerialize,
    utils::blake3, Block,
};
use rand_core::SeedableRng;

use super::msgs::{CheckFromReceiver, CheckFromSender, ExtendFromSender, MaskBits};

/// SPCOT receiver.
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
    ///
    /// See step 1 in Figure 6.
    ///
    pub fn setup(self) -> Receiver<state::Extension> {
        Receiver {
            state: state::Extension {
                unchecked_ws: Vec::default(),
                chis: Vec::default(),
                alphas_and_length: Vec::default(),
                cot_counter: 0,
                exec_counter: 0,
                extended: false,
                hasher: blake3::Hasher::new(),
            },
        }
    }
}

impl Receiver<state::Extension> {
    /// Performs the mask bit step in extension.
    ///
    /// See step 4 in Figure 6.
    ///
    /// # Arguments
    ///
    /// * `h` - The depth of the GGM tree.
    /// * `alpha` - The chosen position.
    /// * `rs` - The message from COT ideal functionality for the receiver. Only the random bits are used.
    pub fn extend_mask_bits(
        &mut self,
        h: usize,
        alpha: u32,
        rs: &[bool],
    ) -> Result<MaskBits, ReceiverError> {
        if self.state.extended {
            return Err(ReceiverError::InvalidState(
                "extension is not allowed".to_string(),
            ));
        }

        if alpha >= (1 << h) {
            return Err(ReceiverError::InvalidInput(
                "the input pos should be no more than 2^h-1".to_string(),
            ));
        }

        if rs.len() != h {
            return Err(ReceiverError::InvalidLength(
                "the length of r should be h".to_string(),
            ));
        }

        // Step 4 in Figure 6

        let bs: Vec<bool> = alpha
            .iter_msb0()
            .skip(32 - h)
            // Computes alpha_i XOR r_i XOR 1.
            .zip(rs.iter())
            .map(|(alpha, &r)| alpha == r)
            .collect();

        // Updates hasher.
        self.state.hasher.update(&bs.to_bytes());

        Ok(MaskBits { bs })
    }

    /// Performs the GGM reconstruction step in extension. This function can be called multiple times before checking.
    ///
    /// See step 5 in Figure 6.
    ///
    /// # Arguments
    ///
    /// * `h` - The depth of the GGM tree.
    /// * `alpha` - The chosen position.
    /// * `ts` - The message from COT ideal functionality for the receiver. Only the chosen blocks are used.
    /// * `extendfs` - The message sent by the sender.
    pub fn extend(
        &mut self,
        h: usize,
        alpha: u32,
        ts: &[Block],
        extendfs: ExtendFromSender,
    ) -> Result<(), ReceiverError> {
        if self.state.extended {
            return Err(ReceiverError::InvalidState(
                "extension is not allowed".to_string(),
            ));
        }

        if alpha >= (1 << h) {
            return Err(ReceiverError::InvalidInput(
                "the input pos should be no more than 2^h-1".to_string(),
            ));
        }

        let ExtendFromSender { ms, sum } = extendfs;
        if ts.len() != h {
            return Err(ReceiverError::InvalidLength(
                "the length of t should be h".to_string(),
            ));
        }

        if ms.len() != h {
            return Err(ReceiverError::InvalidLength(
                "the length of M should be h".to_string(),
            ));
        }

        // Updates hasher
        self.state.hasher.update(&ms.to_bytes());
        self.state.hasher.update(&sum.to_bytes());

        let alpha_bar_vec: Vec<bool> = alpha.iter_msb0().skip(32 - h).map(|a| !a).collect();

        // Step 5 in Figure 6.
        let k: Vec<Block> = ms
            .into_iter()
            .zip(ts)
            .zip(alpha_bar_vec.iter())
            .enumerate()
            .map(|(i, (([m0, m1], &t), &b))| {
                let tweak: Block = bytemuck::cast([i, self.state.exec_counter]);
                if !b {
                    // H(t, i|ell) ^ M0
                    FIXED_KEY_AES.tccr(tweak, t) ^ m0
                } else {
                    // H(t, i|ell) ^ M1
                    FIXED_KEY_AES.tccr(tweak, t) ^ m1
                }
            })
            .collect();

        // Reconstructs GGM tree except `ws[alpha]`.
        let ggm_tree = GgmTree::new(h);
        let mut tree = vec![Block::ZERO; 1 << h];
        ggm_tree.reconstruct(&mut tree, &k, &alpha_bar_vec);

        // Sets `tree[alpha]`, which is `ws[alpha]`.
        tree[alpha as usize] = tree.iter().fold(sum, |acc, &x| acc ^ x);

        self.state.unchecked_ws.extend_from_slice(&tree);
        self.state.alphas_and_length.push((alpha, 1 << h));

        self.state.exec_counter += 1;

        Ok(())
    }

    /// Performs the decomposition and bit-mask steps in check.
    ///
    /// See step 7 in Figure 6.
    ///
    /// # Arguments
    ///
    /// * `x_star` - The message from COT ideal functionality for the receiver. Only the random bits are used.
    pub fn check_pre(&mut self, x_star: &[bool]) -> Result<CheckFromReceiver, ReceiverError> {
        if x_star.len() != CSP {
            return Err(ReceiverError::InvalidLength(format!(
                "the length of x* should be {CSP}"
            )));
        }

        let seed = *self.state.hasher.finalize().as_bytes();
        let mut prg = Prg::from_seed(Block::try_from(&seed[0..16]).unwrap());

        // The sum of all the chi[alpha].
        let mut sum_chi_alpha = Block::ZERO;

        for (alpha, n) in &self.state.alphas_and_length {
            let mut chis = vec![Block::ZERO; *n as usize];
            prg.random_blocks(&mut chis);
            sum_chi_alpha ^= chis[*alpha as usize];
            self.state.chis.extend_from_slice(&chis);
        }

        let x_prime: Vec<bool> = sum_chi_alpha
            .iter_lsb0()
            .zip(x_star)
            .map(|(x, &x_star)| x != x_star)
            .collect();

        Ok(CheckFromReceiver { x_prime })
    }

    /// Performs the final step of the consistency check.
    ///
    /// See step 9 in Figure 6.
    ///
    /// # Arguments
    ///
    /// * `z_star` - The message from COT ideal functionality for the receiver. Only the chosen blocks are used.
    /// * `check` - The hashed value sent by the Sender.
    pub fn check(
        &mut self,
        z_star: &[Block],
        check: CheckFromSender,
    ) -> Result<Vec<(Vec<Block>, u32)>, ReceiverError> {
        let CheckFromSender { hashed_v } = check;

        if z_star.len() != CSP {
            return Err(ReceiverError::InvalidLength(format!(
                "the length of z* should be {CSP}"
            )));
        }

        // Computes the base X^i
        let base: Vec<Block> = (0..CSP).map(|x| bytemuck::cast((1_u128) << x)).collect();

        // Computes Z.
        let mut w = Block::inn_prdt_red(z_star, &base);

        // Computes W.
        w ^= Block::inn_prdt_red(&self.state.chis, &self.state.unchecked_ws);

        // Computes H'(W)
        let hashed_w = Hash::from(blake3(&w.to_bytes()));

        if hashed_v != hashed_w {
            return Err(ReceiverError::ConsistencyCheckFailed);
        }

        self.state.cot_counter += self.state.unchecked_ws.len();
        self.state.extended = true;

        let mut res = Vec::new();
        for (alpha, n) in &self.state.alphas_and_length {
            let tmp: Vec<Block> = self.state.unchecked_ws.drain(..*n as usize).collect();
            res.push((tmp, *alpha));
        }

        Ok(res)
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
    /// In this state the receiver performs COT extension and outputs random choice bits (potentially multiple times).
    pub struct Extension {
        /// Receiver's output blocks.
        pub(super) unchecked_ws: Vec<Block>,
        /// Receiver's random challenges chis.
        pub(super) chis: Vec<Block>,
        /// Stores the alpha and the length in each extend phase.
        pub(super) alphas_and_length: Vec<(u32, u32)>,

        /// Current COT counter
        pub(super) cot_counter: usize,
        /// Current execution counter
        pub(super) exec_counter: usize,
        /// This is to prevent the receiver from extending twice
        pub(super) extended: bool,

        /// A hasher to generate chi seed from the protocol transcript.
        pub(super) hasher: blake3::Hasher,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
