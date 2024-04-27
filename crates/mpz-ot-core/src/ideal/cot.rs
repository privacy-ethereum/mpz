//! Define ideal functionality of COT with random choice bit.

use mpz_core::{prg::Prg, Block};
use serde::{Deserialize, Serialize};

use crate::TransferId;

/// The message that sender receives from the COT functionality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CotMsgForSender {
    /// The transfer id.
    pub id: TransferId,
    /// The random blocks that sender receives from the COT functionality.
    pub qs: Vec<Block>,
}

/// The message that receiver receives from the COT functionality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CotMsgForReceiver {
    /// The transfer id.
    pub id: TransferId,
    /// The random bits that receiver receives from the COT functionality.
    pub rs: Vec<bool>,
    /// The chosen blocks that receiver receives from the COT functionality.
    pub ts: Vec<Block>,
}

/// The ideal COT functionality.
#[derive(Debug)]
pub struct IdealCOT {
    delta: Block,
    transfer_id: TransferId,
    counter: usize,
    prg: Prg,
}

impl IdealCOT {
    /// Initiate the functionality
    pub fn new() -> Self {
        let mut prg = Prg::new();
        let delta = prg.random_block();
        IdealCOT {
            delta,
            transfer_id: TransferId::default(),
            counter: 0,
            prg,
        }
    }

    /// Initiate with a given delta
    pub fn new_with_delta(delta: Block) -> Self {
        let prg = Prg::new();
        IdealCOT {
            delta,
            transfer_id: TransferId::default(),
            counter: 0,
            prg,
        }
    }

    /// Output delta
    pub fn delta(&self) -> Block {
        self.delta
    }

    /// Performs the extension with random choice bits.
    ///
    /// # Argument
    ///
    /// * `count` - The number of COT to extend.
    pub fn extend(&mut self, count: usize) -> (CotMsgForSender, CotMsgForReceiver) {
        let mut qs = vec![Block::ZERO; count];
        let mut rs = vec![false; count];

        self.prg.random_blocks(&mut qs);
        self.prg.random_bools(&mut rs);

        let ts: Vec<Block> = qs
            .iter()
            .zip(rs.iter())
            .map(|(&q, &r)| if r { q ^ self.delta } else { q })
            .collect();

        let id = self.transfer_id.next();
        self.counter += count;

        (CotMsgForSender { id, qs }, CotMsgForReceiver { id, rs, ts })
    }
}

impl Default for IdealCOT {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ideal_cot_test() {
        let num = 100;
        let mut ideal_cot = IdealCOT::new();
        let delta = ideal_cot.delta();
        let (CotMsgForSender { qs, .. }, CotMsgForReceiver { rs, ts, .. }) = ideal_cot.extend(num);

        assert!(qs.into_iter().zip(ts).zip(rs).all(|((q, t), r)| {
            if !r {
                q == t
            } else {
                q == t ^ delta
            }
        }));
    }
}
