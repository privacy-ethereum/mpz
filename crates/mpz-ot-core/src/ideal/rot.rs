//! Ideal Random Oblivious Transfer functionality.

use mpz_core::{prg::Prg, Block};
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use rand_chacha::ChaCha8Rng;

use crate::{ROTReceiverOutput, ROTSenderOutput, TransferId};

/// The ideal ROT functionality.
#[derive(Debug)]
pub struct IdealROT {
    transfer_id: TransferId,
    counter: usize,
    prg: Prg,
}

impl IdealROT {
    /// Creates a new ideal ROT functionality.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed for the PRG.
    pub fn new(seed: Block) -> Self {
        IdealROT {
            transfer_id: TransferId::default(),
            counter: 0,
            prg: Prg::from_seed(seed),
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

    /// Executes random oblivious transfers.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of OTs to execute.
    pub fn random<T: Copy>(
        &mut self,
        count: usize,
    ) -> (ROTSenderOutput<[T; 2]>, ROTReceiverOutput<bool, T>)
    where
        Standard: Distribution<T>,
    {
        let mut choices = vec![false; count];

        self.prg.random_bools(&mut choices);

        let msgs: Vec<[T; 2]> = (0..count)
            .map(|_| [self.prg.sample(Standard), self.prg.sample(Standard)])
            .collect();

        let chosen = choices
            .iter()
            .zip(msgs.iter())
            .map(|(&choice, [zero, one])| if choice { *one } else { *zero })
            .collect();

        self.counter += count;
        let id = self.transfer_id.next();

        (
            ROTSenderOutput { id, msgs },
            ROTReceiverOutput {
                id,
                choices,
                msgs: chosen,
            },
        )
    }

    /// Executes random oblivious transfers with choices provided by the receiver.
    ///
    /// # Arguments
    ///
    /// * `choices` - The choices made by the receiver.
    pub fn random_with_choices<T: Copy>(
        &mut self,
        choices: Vec<bool>,
    ) -> (ROTSenderOutput<[T; 2]>, ROTReceiverOutput<bool, T>)
    where
        Standard: Distribution<T>,
    {
        let msgs: Vec<[T; 2]> = (0..choices.len())
            .map(|_| [self.prg.sample(Standard), self.prg.sample(Standard)])
            .collect();

        let chosen = choices
            .iter()
            .zip(msgs.iter())
            .map(|(&choice, [zero, one])| if choice { *one } else { *zero })
            .collect();

        self.counter += choices.len();
        let id = self.transfer_id.next();

        (
            ROTSenderOutput { id, msgs },
            ROTReceiverOutput {
                id,
                choices,
                msgs: chosen,
            },
        )
    }
}

impl Default for IdealROT {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        Self::new(rng.gen())
    }
}

#[cfg(test)]
mod tests {
    use crate::test::assert_rot;

    use super::*;

    #[test]
    fn test_ideal_rot() {
        let (
            ROTSenderOutput { msgs, .. },
            ROTReceiverOutput {
                choices,
                msgs: received,
                ..
            },
        ) = IdealROT::default().random::<Block>(100);

        assert_rot(&choices, &msgs, &received)
    }

    #[test]
    fn test_ideal_rot_with_choices() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let mut choices = vec![false; 100];
        rng.fill(&mut choices[..]);

        let (
            ROTSenderOutput { msgs, .. },
            ROTReceiverOutput {
                choices,
                msgs: received,
                ..
            },
        ) = IdealROT::default().random_with_choices::<Block>(choices);

        assert_rot(&choices, &msgs, &received)
    }
}
