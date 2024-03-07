use mpz_core::{commit::HashCommit, Block};

use crate::{
    msgs::{ReceiverPayload, SenderCommitment, SenderPayload},
    CointossError,
};

/// A coin-toss sender.
#[derive(Debug)]
pub struct Sender<S: sender_state::State = sender_state::Initialized> {
    state: S,
}

impl Sender {
    /// Create a new sender.
    pub fn new(seeds: Vec<Block>) -> Self {
        Self {
            state: sender_state::Initialized { seeds },
        }
    }

    /// Sends the coin-toss commitment.
    pub fn send(self) -> (Sender<sender_state::Committed>, SenderCommitment) {
        let sender_state::Initialized { seeds } = self.state;

        let (decommitment, commitment) = seeds.clone().hash_commit();

        (
            Sender {
                state: sender_state::Committed {
                    seeds,
                    decommitment,
                },
            },
            SenderCommitment { commitment },
        )
    }
}

impl Sender<sender_state::Committed> {
    /// Receives the receiver's payload and computes the output of the
    /// coin-toss.
    pub fn receive(
        self,
        payload: ReceiverPayload,
    ) -> Result<(Vec<Block>, Sender<sender_state::Received>), CointossError> {
        let receiver_seeds = payload.seeds;
        let sender_seeds = self.state.seeds;

        if sender_seeds.len() != receiver_seeds.len() {
            return Err(CointossError::CountMismatch {
                expected: sender_seeds.len(),
                actual: receiver_seeds.len(),
            });
        }

        let seeds = sender_seeds
            .into_iter()
            .zip(receiver_seeds)
            .map(|(sender_seed, receiver_seed)| sender_seed ^ receiver_seed)
            .collect();

        Ok((
            seeds,
            Sender {
                state: sender_state::Received {
                    decommitment: self.state.decommitment,
                },
            },
        ))
    }
}

impl Sender<sender_state::Received> {
    /// Finalizes the coin-toss, decommitting the sender's seeds.
    pub fn finalize(self) -> SenderPayload {
        SenderPayload {
            decommitment: self.state.decommitment,
        }
    }
}

/// Coin-toss sender state.
pub mod sender_state {
    use mpz_core::commit::Decommitment;

    use super::*;

    mod sealed {
        use super::*;

        pub trait Sealed {}

        impl Sealed for Initialized {}
        impl Sealed for Committed {}
        impl Sealed for Received {}
    }

    /// The sender's state.
    pub trait State: sealed::Sealed {}

    /// The sender's initial state.
    pub struct Initialized {
        pub(super) seeds: Vec<Block>,
    }

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The sender's committed state.
    pub struct Committed {
        pub(super) seeds: Vec<Block>,
        pub(super) decommitment: Decommitment<Vec<Block>>,
    }

    impl State for Committed {}

    opaque_debug::implement!(Committed);

    /// The sender's state after they've received the payload from the
    /// receiver.
    pub struct Received {
        pub(super) decommitment: Decommitment<Vec<Block>>,
    }

    impl State for Received {}

    opaque_debug::implement!(Received);
}
