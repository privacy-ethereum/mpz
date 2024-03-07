//! Define ideal functionality of COT with random choice bit.

use mpz_core::{prg::Prg, Block};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The message that sender receives from the COT functionality.
pub struct CotMsgForSender {
    /// The random blocks that sender receives from the COT functionality.
    pub qs: Vec<Block>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The message that receiver receives from the COT functionality.
pub struct CotMsgForReceiver {
    /// The random bits that receiver receives from the COT functionality.
    pub rs: Vec<bool>,
    /// The chosen blocks that receiver receives from the COT functionality.
    pub ts: Vec<Block>,
}
#[allow(missing_docs)]
pub struct IdealCOT {
    delta: Block,
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
            counter: 0,
            prg,
        }
    }

    /// Initiate with a given delta
    pub fn new_with_delta(delta: Block) -> Self {
        let prg = Prg::new();
        IdealCOT {
            delta,
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
    /// * `counter` - The number of COT to extend.
    pub fn extend(&mut self, counter: usize) -> (CotMsgForSender, CotMsgForReceiver) {
        let mut qs = vec![Block::ZERO; counter];
        let mut rs = vec![false; counter];

        self.prg.random_blocks(&mut qs);
        self.prg.random_bools(&mut rs);

        let ts: Vec<Block> = qs
            .iter()
            .zip(rs.iter())
            .map(|(&q, &r)| if r { q ^ self.delta } else { q })
            .collect();

        self.counter += counter;
        (CotMsgForSender { qs }, CotMsgForReceiver { rs, ts })
    }

    /// Checks if the outputs satisfy the relation with Delta, this is only used for test.
    ///
    /// # Arguments
    ///
    /// * `sender_msg` - The message that the ideal COT sends to the sender.
    /// * `receiver_msg` - The message that the ideal COT sends to the receiver.
    pub fn check(&self, sender_msg: CotMsgForSender, receiver_msg: CotMsgForReceiver) -> bool {
        let CotMsgForSender { qs } = sender_msg;
        let CotMsgForReceiver { rs, ts } = receiver_msg;

        qs.into_iter().zip(ts).zip(rs).all(
            |((q, t), r)| {
                if !r {
                    q == t
                } else {
                    q == t ^ self.delta
                }
            },
        )
    }
}

impl Default for IdealCOT {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use crate::ideal::ideal_cot::IdealCOT;

    #[test]
    fn ideal_cot_test() {
        let num = 100;
        let mut ideal_cot = IdealCOT::new();
        let (sender, receiver) = ideal_cot.extend(num);

        assert!(ideal_cot.check(sender, receiver));
    }
}
