//! Ideal Chosen-Message Oblivious Transfer functionality.

use crate::{OTReceiverOutput, OTSenderOutput, TransferId};

/// The ideal OT functionality.
#[derive(Debug, Default)]
pub struct IdealOT {
    transfer_id: TransferId,
    counter: usize,
    /// Log of choices made by the receiver.
    choices: Vec<bool>,
}

impl IdealOT {
    /// Creates a new ideal OT functionality.
    pub fn new() -> Self {
        IdealOT {
            transfer_id: TransferId::default(),
            counter: 0,
            choices: Vec::new(),
        }
    }

    /// Returns the current transfer id.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Returns the number of OTs executed.
    pub fn count(&self) -> usize {
        self.counter
    }

    /// Returns the choices made by the receiver.
    pub fn choices(&self) -> &[bool] {
        &self.choices
    }

    /// Executes chosen-message oblivious transfers.
    ///
    /// # Arguments
    ///
    /// * `choices` - The choices made by the receiver.
    /// * `msgs` - The sender's messages.
    pub fn chosen<T: Copy>(
        &mut self,
        choices: Vec<bool>,
        msgs: Vec<[T; 2]>,
    ) -> (OTSenderOutput, OTReceiverOutput<T>) {
        let chosen = choices
            .iter()
            .zip(msgs.iter())
            .map(|(&choice, [zero, one])| if choice { *one } else { *zero })
            .collect();

        self.counter += choices.len();
        self.choices.extend(choices);
        let id = self.transfer_id.next();

        (OTSenderOutput { id }, OTReceiverOutput { id, msgs: chosen })
    }
}

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    fn test_ideal_ot() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let mut choices = vec![false; 100];
        rng.fill(&mut choices[..]);

        let msgs: Vec<[Block; 2]> = (0..100).map(|_| [rng.gen(), rng.gen()]).collect();

        let (OTSenderOutput { .. }, OTReceiverOutput { msgs: chosen, .. }) =
            IdealOT::default().chosen(choices.clone(), msgs.clone());

        assert!(choices.into_iter().zip(msgs.into_iter().zip(chosen)).all(
            |(choice, (msg, chosen))| {
                if choice {
                    chosen == msg[1]
                } else {
                    chosen == msg[0]
                }
            }
        ));
    }
}
