//! Define ideal functionality of MPCOT.

use mpz_core::{prg::Prg, Block};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The message that sender receives from the MPCOT functionality.
pub struct MpcotMsgForSender {
    /// The random blocks that sender receives from the MPCOT functionality.
    pub s: Vec<Block>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// The message that receiver receives from the MPCOT functionality.
pub struct MpcotMsgForReceiver {
    /// The random blocks that receiver receives from the MPCOT functionality.
    pub r: Vec<Block>,
}

#[allow(missing_docs)]
pub struct IdealMpcot {
    pub delta: Block,
    pub counter: usize,
    pub prg: Prg,
}

impl IdealMpcot {
    /// Initiate the functionality.
    pub fn init() -> Self {
        let mut prg = Prg::new();
        let delta = prg.random_block();
        IdealMpcot {
            delta,
            counter: 0,
            prg,
        }
    }

    /// Initiate with a given delta.
    pub fn init_with_delta(delta: Block) -> Self {
        let prg = Prg::new();
        IdealMpcot {
            delta,
            counter: 0,
            prg,
        }
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
        t: usize,
        n: usize,
    ) -> (MpcotMsgForSender, MpcotMsgForReceiver) {
        assert_eq!(alphas.len(), t);
        assert!(t < n);
        let mut s = vec![Block::ZERO; n];
        let mut r = vec![Block::ZERO; n];
        self.prg.random_blocks(&mut s);
        r.copy_from_slice(&s);

        for alpha in alphas {
            assert!((*alpha as usize) < n);
            r[*alpha as usize] ^= self.delta;

            self.counter += 1;
        }
        (MpcotMsgForSender { s }, MpcotMsgForReceiver { r })
    }

    /// Performs the checks.
    ///
    /// # Arguments
    ///
    /// * `sender_msg` - The message that the ideal MPCOT sends to the sender.
    /// * `receiver_msg` - The message that the ideal MPCOT sends to the receiver.
    /// * `alphas` - The positions in each extension.
    /// * `n` - The length of the vector.
    pub fn check(
        &self,
        sender_msg: MpcotMsgForSender,
        receiver_msg: MpcotMsgForReceiver,
        alphas: &[u32],
        t: usize,
        n: usize,
    ) -> bool {
        assert_eq!(alphas.len(), t);
        let MpcotMsgForSender { mut s } = sender_msg;
        let MpcotMsgForReceiver { r } = receiver_msg;

        for alpha in alphas {
            assert!((*alpha as usize) < n);
            s[*alpha as usize] ^= self.delta;
        }

        let res = s.iter_mut().zip(r.iter()).all(|(s, r)| *s == *r);
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::ideal::ideal_mpcot::IdealMpcot;

    #[test]
    fn ideal_mpcot_test() {
        let mut ideal_mpcot = IdealMpcot::init();

        let (sender_msg, receiver_msg) = ideal_mpcot.extend(&[1, 3, 4, 6], 4, 20);
        assert!(ideal_mpcot.check(sender_msg, receiver_msg, &[1, 3, 4, 6], 4, 20));
    }
}
