//! Ideal functionality for single-point correlated OT.

use mpz_core::{prg::Prg, Block};

use crate::{SPCOTReceiverOutput, SPCOTSenderOutput, TransferId};

/// The ideal SPCOT functionality.
#[derive(Debug)]
pub struct IdealSpcot {
    delta: Block,
    transfer_id: TransferId,
    counter: usize,
    prg: Prg,
}

impl IdealSpcot {
    /// Initiate the functionality.
    pub fn new() -> Self {
        let mut prg = Prg::new();
        let delta = prg.random_block();
        IdealSpcot {
            delta,
            transfer_id: TransferId::default(),
            counter: 0,
            prg,
        }
    }

    /// Initiate with a given delta
    pub fn new_with_delta(delta: Block) -> Self {
        let prg = Prg::new();
        IdealSpcot {
            delta,
            transfer_id: TransferId::default(),
            counter: 0,
            prg,
        }
    }

    /// Performs the batch extension of SPCOT.
    ///
    /// # Argument
    ///
    /// * `pos` - The positions in each extension.
    pub fn extend(
        &mut self,
        pos: &[(usize, u32)],
    ) -> (SPCOTSenderOutput<Block>, SPCOTReceiverOutput<Block>) {
        let mut v = vec![];
        let mut w = vec![];

        for (n, alpha) in pos {
            assert!((*alpha as usize) < *n);
            let mut v_tmp = vec![Block::ZERO; *n];
            self.prg.random_blocks(&mut v_tmp);
            let mut w_tmp = v_tmp.clone();
            w_tmp[*alpha as usize] ^= self.delta;

            v.push(v_tmp);
            w.push(w_tmp);
            self.counter += n;
        }

        let id = self.transfer_id.next();

        (SPCOTSenderOutput { id, v }, SPCOTReceiverOutput { id, w })
    }
}

impl Default for IdealSpcot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ideal_spcot_test() {
        let mut ideal_spcot = IdealSpcot::new();
        let delta = ideal_spcot.delta;

        let pos = [(10, 2), (20, 3)];

        let (SPCOTSenderOutput { mut v, .. }, SPCOTReceiverOutput { w, .. }) =
            ideal_spcot.extend(&pos);

        v.iter_mut()
            .zip(w.iter())
            .zip(pos.iter())
            .for_each(|((v, w), (n, p))| {
                assert_eq!(v.len(), *n);
                assert_eq!(w.len(), *n);
                v[*p as usize] ^= delta;
            });

        assert!(v
            .iter()
            .zip(w.iter())
            .all(|(v, w)| v.iter().zip(w.iter()).all(|(x, y)| *x == *y)));
    }
}
