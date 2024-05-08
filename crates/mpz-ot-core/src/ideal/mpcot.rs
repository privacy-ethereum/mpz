//! Ideal functionality for the multi-point correlated OT.

use mpz_core::{prg::Prg, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{MPCOTReceiverOutput, MPCOTSenderOutput, TransferId};

/// The ideal MPCOT functionality.
#[derive(Debug)]
pub struct IdealMpcot {
    delta: Block,
    transfer_id: TransferId,
    counter: usize,
    prg: Prg,
}

impl IdealMpcot {
    /// Creates a new ideal MPCOT functionality.
    pub fn new(seed: Block, delta: Block) -> Self {
        IdealMpcot {
            delta,
            transfer_id: TransferId::default(),
            counter: 0,
            prg: Prg::from_seed(seed),
        }
    }

    /// Returns the correlation, delta.
    pub fn delta(&self) -> Block {
        self.delta
    }

    /// Sets the correlation, delta.
    pub fn set_delta(&mut self, delta: Block) {
        self.delta = delta;
    }

    /// Performs the extension of MPCOT.
    ///
    /// # Argument
    ///
    /// * `alphas` - The positions in each extension.
    /// * `n` - The length of the vector.
    pub fn extend(
        &mut self,
        alphas: &[u32],
        n: usize,
    ) -> (MPCOTSenderOutput<Block>, MPCOTReceiverOutput<Block>) {
        assert!(alphas.len() < n);
        let mut s = vec![Block::ZERO; n];
        let mut r = vec![Block::ZERO; n];
        self.prg.random_blocks(&mut s);
        r.copy_from_slice(&s);

        for alpha in alphas {
            assert!((*alpha as usize) < n);
            r[*alpha as usize] ^= self.delta;

            self.counter += 1;
        }

        let id = self.transfer_id.next();

        (MPCOTSenderOutput { id, s }, MPCOTReceiverOutput { id, r })
    }
}

impl Default for IdealMpcot {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        IdealMpcot::new(rng.gen(), rng.gen())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ideal_mpcot_test() {
        let mut ideal = IdealMpcot::default();

        let alphas = [1, 3, 4, 6];
        let n = 20;

        let (MPCOTSenderOutput { mut s, .. }, MPCOTReceiverOutput { r, .. }) =
            ideal.extend(&alphas, n);

        for alpha in alphas {
            assert!((alpha as usize) < n);
            s[alpha as usize] ^= ideal.delta();
        }

        assert!(s.iter_mut().zip(r.iter()).all(|(s, r)| *s == *r));
    }
}
