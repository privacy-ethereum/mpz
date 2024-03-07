//! SPCOT sender.
use crate::ferret::{spcot::error::SenderError, CSP};
use mpz_core::{
    aes::FIXED_KEY_AES, ggm_tree::GgmTree, hash::Hash, prg::Prg, serialize::CanonicalSerialize,
    utils::blake3, Block,
};
use rand_core::SeedableRng;

use super::msgs::{CheckFromReceiver, CheckFromSender, ExtendFromSender, MaskBits};

/// SPCOT sender.
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
    /// See step 1 in Figure 6.
    ///
    /// # Arguments
    ///
    /// * `delta` - The sender's global secret.
    /// * `seed`  - The random seed to generate PRG.
    pub fn setup(self, delta: Block, seed: Block) -> Sender<state::Extension> {
        Sender {
            state: state::Extension {
                delta,
                unchecked_vs: Vec::default(),
                vs_length: Vec::default(),
                cot_counter: 0,
                exec_counter: 0,
                extended: false,
                prg: Prg::from_seed(seed),
                hasher: blake3::Hasher::new(),
            },
        }
    }
}

impl Sender<state::Extension> {
    /// Performs the SPCOT extension.
    ///
    /// See Step 1-5 in Figure 6.
    ///
    /// # Arguments
    ///
    /// * `h` - The depth of the GGM tree.
    /// * `qs`- The blocks received by calling the COT functionality.
    /// * `mask`- The mask bits sent by the receiver.
    pub fn extend(
        &mut self,
        h: usize,
        qs: &[Block],
        mask: MaskBits,
    ) -> Result<ExtendFromSender, SenderError> {
        if self.state.extended {
            return Err(SenderError::InvalidState(
                "extension is not allowed".to_string(),
            ));
        }

        if qs.len() != h {
            return Err(SenderError::InvalidLength(
                "the length of q should be h".to_string(),
            ));
        }

        let MaskBits { bs } = mask;

        if bs.len() != h {
            return Err(SenderError::InvalidLength(
                "the length of b should be h".to_string(),
            ));
        }

        // Updates hasher.
        self.state.hasher.update(&bs.to_bytes());

        // Step 3-4, Figure 6.

        // Generates a GGM tree with depth h and seed s.
        let s = self.state.prg.random_block();
        let ggm_tree = GgmTree::new(h);
        let mut k0 = vec![Block::ZERO; h];
        let mut k1 = vec![Block::ZERO; h];
        let mut tree = vec![Block::ZERO; 1 << h];
        ggm_tree.gen(s, &mut tree, &mut k0, &mut k1);

        // Stores the tree, i.e., the possible output of sender.
        self.state.unchecked_vs.extend_from_slice(&tree);

        // Stores the length of this extension.
        self.state.vs_length.push(1 << h);

        // Computes the sum of the leaves and delta.
        let sum = tree.iter().fold(self.state.delta, |acc, &x| acc ^ x);

        // Computes M0 and M1.
        let mut ms: Vec<[Block; 2]> = Vec::with_capacity(qs.len());
        for (((i, &q), b), (k0, k1)) in qs.iter().enumerate().zip(bs).zip(k0.into_iter().zip(k1)) {
            let mut m = if b {
                [q ^ self.state.delta, q]
            } else {
                [q, q ^ self.state.delta]
            };
            let tweak: Block = bytemuck::cast([i, self.state.exec_counter]);
            FIXED_KEY_AES.tccr_many(&[tweak, tweak], &mut m);
            m[0] ^= k0;
            m[1] ^= k1;
            ms.push(m);
        }

        // Updates hasher
        self.state.hasher.update(&ms.to_bytes());
        self.state.hasher.update(&sum.to_bytes());

        self.state.exec_counter += 1;

        Ok(ExtendFromSender { ms, sum })
    }

    /// Performs the consistency check for the resulting COTs.
    ///
    /// See Step 6-9 in Figure 6.
    ///
    /// # Arguments
    ///
    /// * `y_star` - The blocks received from the ideal functionality for the check.
    /// * `checkfr` - The bits received from the receiver for the check.
    pub fn check(
        &mut self,
        y_star: &[Block],
        checkfr: CheckFromReceiver,
    ) -> Result<(Vec<Vec<Block>>, CheckFromSender), SenderError> {
        let CheckFromReceiver { x_prime } = checkfr;

        if y_star.len() != CSP {
            return Err(SenderError::InvalidLength(format!(
                "the length of y* should be {CSP}"
            )));
        }

        if x_prime.len() != CSP {
            return Err(SenderError::InvalidLength(format!(
                "the length of x' should be {CSP}"
            )));
        }

        // Step 8 in Figure 6.

        // Computes y = y_star + x' * Delta
        let y: Vec<Block> = y_star
            .iter()
            .zip(x_prime.iter())
            .map(|(&y, &x)| if x { y ^ self.state.delta } else { y })
            .collect();

        // Computes the base X^i
        let base: Vec<Block> = (0..CSP).map(|x| bytemuck::cast((1_u128) << x)).collect();

        // Computes Y
        let mut v = Block::inn_prdt_red(&y, &base);

        // Computes V
        let seed = *self.state.hasher.finalize().as_bytes();
        let mut prg = Prg::from_seed(Block::try_from(&seed[0..16]).unwrap());

        let mut chis = Vec::new();
        for n in &self.state.vs_length {
            let mut chi = vec![Block::ZERO; *n as usize];
            prg.random_blocks(&mut chi);
            chis.extend_from_slice(&chi);
        }
        v ^= Block::inn_prdt_red(&chis, &self.state.unchecked_vs);

        // Computes H'(V)
        let hashed_v = Hash::from(blake3(&v.to_bytes()));

        self.state.cot_counter += self.state.unchecked_vs.len();

        let mut res = Vec::new();
        for n in &self.state.vs_length {
            let tmp: Vec<Block> = self.state.unchecked_vs.drain(..*n as usize).collect();
            res.push(tmp);
        }

        self.state.extended = true;

        Ok((res, CheckFromSender { hashed_v }))
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
    /// In this state the sender performs COT extension with random choice bits (potentially multiple times). Also in this state the sender responds to COT requests.
    pub struct Extension {
        /// Sender's global secret.
        pub(super) delta: Block,
        /// Sender's output blocks, support multiple extensions.
        pub(super) unchecked_vs: Vec<Block>,
        /// Store the length of each extension.
        pub(super) vs_length: Vec<u32>,

        /// Current COT counter
        pub(super) cot_counter: usize,
        /// Current execution counter
        pub(super) exec_counter: usize,
        /// This is to prevent the receiver from extending twice
        pub(super) extended: bool,

        /// A PRG to generate random strings.
        pub(super) prg: Prg,
        /// A hasher to generate chi seed.
        pub(super) hasher: blake3::Hasher,
    }

    impl State for Extension {}

    opaque_debug::implement!(Extension);
}
