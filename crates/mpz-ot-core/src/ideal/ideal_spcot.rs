//! Define ideal functionality of SPCOT.

use mpz_core::{prg::Prg, Block};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The message that sender receivers from the SPCOT functionality.
pub struct SpcotMsgForSender {
    /// The random blocks that sender receives from the SPCOT functionality.
    pub v: Vec<Vec<Block>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The message that receiver receives from the SPCOT functionality.
pub struct SpcotMsgForReceiver {
    /// The random blocks that receiver receives from the SPCOT functionality.
    pub w: Vec<Vec<Block>>,
}

#[allow(missing_docs)]
pub struct IdealSpcot {
    delta: Block,
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
            counter: 0,
            prg,
        }
    }

    /// Initiate with a given delta
    pub fn new_with_delta(delta: Block) -> Self {
        let prg = Prg::new();
        IdealSpcot {
            delta,
            counter: 0,
            prg,
        }
    }

    /// Performs the batch extension of SPCOT.
    ///
    /// # Argument
    ///
    /// * `pos` - The positions in each extension.
    pub fn extend(&mut self, pos: &[(usize, u32)]) -> (SpcotMsgForSender, SpcotMsgForReceiver) {
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
        (SpcotMsgForSender { v }, SpcotMsgForReceiver { w })
    }

    /// Checks if the outputs satisfy the relation with Delta, this is only used for test.
    ///
    /// # Arguments
    ///
    /// * `sender_msg` - The message that the ideal SPCOT sends to the sender.
    /// * `receiver_msg` - The message that the ideal SPCOT sends to the receiver.
    pub fn check(
        &self,
        sender_msg: SpcotMsgForSender,
        receiver_msg: SpcotMsgForReceiver,
        pos: &[(usize, u32)],
    ) -> bool {
        let SpcotMsgForSender { mut v } = sender_msg;
        let SpcotMsgForReceiver { w } = receiver_msg;

        v.iter_mut()
            .zip(w.iter())
            .zip(pos.iter())
            .for_each(|((v, w), (n, p))| {
                assert_eq!(v.len(), *n);
                assert_eq!(w.len(), *n);
                v[*p as usize] ^= self.delta;
            });

        let res = v
            .iter()
            .zip(w.iter())
            .all(|(v, w)| v.iter().zip(w.iter()).all(|(x, y)| *x == *y));
        res
    }
}

impl Default for IdealSpcot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::ideal::ideal_spcot::IdealSpcot;

    #[test]
    fn ideal_spcot_test() {
        let mut ideal_spcot = IdealSpcot::new();

        let (sender_msg, receiver_msg) = ideal_spcot.extend(&[(10, 2), (20, 3)]);

        assert!(ideal_spcot.check(sender_msg, receiver_msg, &[(10, 2), (20, 3)]));
    }
}
