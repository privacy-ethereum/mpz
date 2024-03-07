use mpz_core::{hash::Hash, Block};

use crate::{
    msgs::{ReceiverPayload, SenderCommitment, SenderPayload},
    CointossError,
};

/// A coin-toss receiver.
#[derive(Debug)]
pub struct Receiver<S: receiver_state::State = receiver_state::Initialized> {
    state: S,
}

impl Receiver {
    /// Create a new receiver.
    pub fn new(seeds: Vec<Block>) -> Self {
        Self {
            state: receiver_state::Initialized { seeds },
        }
    }

    /// Reveals the receiver's seeds after receiving the sender's commitment.
    pub fn reveal(
        self,
        sender_commitment: SenderCommitment,
    ) -> Result<(Receiver<receiver_state::Received>, ReceiverPayload), CointossError> {
        let receiver_state::Initialized { seeds } = self.state;

        Ok((
            Receiver {
                state: receiver_state::Received {
                    seeds: seeds.clone(),
                    commitment: sender_commitment.commitment,
                },
            },
            ReceiverPayload { seeds },
        ))
    }
}

impl Receiver<receiver_state::Received> {
    /// Finalizes the coin-toss, returning the random seeds.
    pub fn finalize(self, payload: SenderPayload) -> Result<Vec<Block>, CointossError> {
        let decommitment = payload.decommitment;
        let receiver_seeds = self.state.seeds;
        let commitment = self.state.commitment;

        if decommitment.data().len() != receiver_seeds.len() {
            return Err(CointossError::CountMismatch {
                expected: decommitment.data().len(),
                actual: receiver_seeds.len(),
            });
        }

        decommitment.verify(&commitment)?;

        Ok(decommitment
            .into_inner()
            .into_iter()
            .zip(receiver_seeds)
            .map(|(decommitment, receiver_seed)| receiver_seed ^ decommitment)
            .collect::<Vec<_>>())
    }
}

/// Coin-toss receiver state.
pub mod receiver_state {
    use super::*;

    mod sealed {
        use super::*;

        pub trait Sealed {}

        impl Sealed for Initialized {}
        impl Sealed for Received {}
    }

    /// The receiver's state.
    pub trait State: sealed::Sealed {}

    /// The receiver's initial state.
    pub struct Initialized {
        pub(super) seeds: Vec<Block>,
    }

    impl State for Initialized {}

    opaque_debug::implement!(Initialized);

    /// The receiver's state after receiving the sender's commitment and revealing one's own seed.
    pub struct Received {
        pub(super) seeds: Vec<Block>,
        pub(super) commitment: Hash,
    }

    impl State for Received {}

    opaque_debug::implement!(Received);
}
