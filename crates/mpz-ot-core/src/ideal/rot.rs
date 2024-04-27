//! Define ideal functionality of ROT with random choice bit.

use mpz_core::{prg::Prg, Block};
use serde::{Deserialize, Serialize};

use crate::TransferId;

/// The message that sender receives from the ROT functionality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RotMsgForSender {
    /// The transfer id.
    pub id: TransferId,
    /// The random blocks that sender receives from the ROT functionality.
    pub qs: Vec<[Block; 2]>,
}

/// The message that receiver receives from the ROT functionality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RotMsgForReceiver {
    /// The transfer id.
    pub id: TransferId,
    /// The random bits that receiver receives from the ROT functionality.
    pub rs: Vec<bool>,
    /// The chosen blocks that receiver receives from the ROT functionality.
    pub ts: Vec<Block>,
}

/// An ideal functionality for random OT
#[derive(Debug)]
pub struct IdealROT {
    transfer_id: TransferId,
    counter: usize,
    prg: Prg,
}

impl IdealROT {
    /// Initiate the functionality
    pub fn new() -> Self {
        let prg = Prg::new();
        IdealROT {
            transfer_id: TransferId::default(),
            counter: 0,
            prg,
        }
    }

    /// Performs the extension with random choice bits.
    ///
    /// # Argument
    ///
    /// * `counter` - The number of ROT to extend.
    pub fn extend(&mut self, counter: usize) -> (RotMsgForSender, RotMsgForReceiver) {
        let mut qs1 = vec![Block::ZERO; counter];
        let mut qs2 = vec![Block::ZERO; counter];

        self.prg.random_blocks(&mut qs1);
        self.prg.random_blocks(&mut qs2);

        let qs: Vec<[Block; 2]> = qs1.iter().zip(qs2).map(|(&q1, q2)| [q1, q2]).collect();

        let mut rs = vec![false; counter];

        self.prg.random_bools(&mut rs);

        let ts: Vec<Block> = qs
            .iter()
            .zip(rs.iter())
            .map(|(&q, &r)| q[r as usize])
            .collect();

        let id = self.transfer_id.next();
        self.counter += counter;

        (RotMsgForSender { id, qs }, RotMsgForReceiver { id, rs, ts })
    }
}

impl Default for IdealROT {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ideal_rot_test() {
        let num = 100;
        let mut ideal_rot = IdealROT::new();
        let (RotMsgForSender { qs, .. }, RotMsgForReceiver { rs, ts, .. }) = ideal_rot.extend(num);

        assert!(qs
            .iter()
            .zip(ts)
            .zip(rs)
            .all(|((q, t), r)| q[r as usize] == t));
    }
}
