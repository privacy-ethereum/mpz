//! Ideal Random Oblivious Transfer functionality.

use std::{
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{new_output, MaybeDone, Sender};
use mpz_core::{prg::Prg, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    rot::{ROTReceiver, ROTReceiverOutput, ROTSender, ROTSenderOutput},
    TransferId,
};

type Error = IdealROTError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Default)]
struct SenderState {
    alloc: usize,
    transfer_id: TransferId,
    queue: Vec<(usize, Sender<ROTSenderOutput<[Block; 2]>>)>,
}

#[derive(Debug, Default)]
struct ReceiverState {
    alloc: usize,
    transfer_id: TransferId,
    queue: Vec<(usize, Sender<ROTReceiverOutput<bool, Block>>)>,
}

/// The ideal ROT functionality.
#[derive(Debug, Clone)]
pub struct IdealROT {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    prg: Prg,
    sender_state: SenderState,
    receiver_state: ReceiverState,
    keys: Vec<[Block; 2]>,
    msgs: Vec<Block>,
    choices: Vec<bool>,
}

impl IdealROT {
    /// Creates a new ideal ROT functionality.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed for the PRG.
    pub fn new(seed: Block) -> Self {
        IdealROT {
            inner: Arc::new(Mutex::new(Inner {
                prg: Prg::from_seed(seed),
                sender_state: SenderState::default(),
                receiver_state: ReceiverState::default(),
                keys: Vec::new(),
                msgs: Vec::new(),
                choices: Vec::new(),
            })),
        }
    }

    /// Returns `count` random ROTs.
    pub fn transfer(
        &mut self,
        count: usize,
    ) -> Result<(ROTSenderOutput<[Block; 2]>, ROTReceiverOutput<bool, Block>)> {
        Ok((self.try_send_rot(count)?, self.try_recv_rot(count)?))
    }

    /// Returns `true` if the functionality wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        let this = self.inner.lock().unwrap();
        let sender_count = this.sender_state.alloc;
        let receiver_count = this.receiver_state.alloc;

        sender_count > 0 || receiver_count > 0
    }

    /// Flushes the functionality.
    pub fn flush(&mut self) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        if this.sender_state.alloc != this.receiver_state.alloc {
            return Err(Error::new(format!(
                "sender and receiver alloc out of sync: {} != {}",
                this.sender_state.alloc, this.receiver_state.alloc
            )));
        }

        let count = this.sender_state.alloc;

        let keys = (0..count)
            .map(|_| [this.prg.gen(), this.prg.gen()])
            .collect::<Vec<_>>();
        let choices = (0..count).map(|_| this.prg.gen()).collect::<Vec<_>>();
        let msgs = keys
            .iter()
            .zip(&choices)
            .map(|(keys, choice)| keys[*choice as usize])
            .collect::<Vec<_>>();

        this.keys.extend_from_slice(&keys);
        this.choices.extend_from_slice(&choices);
        this.msgs.extend_from_slice(&msgs);

        this.sender_state.alloc = 0;
        this.receiver_state.alloc = 0;

        let mut i = 0;
        for (count, sender) in mem::take(&mut this.sender_state.queue) {
            let keys = this.keys[i..i + count].to_vec();
            i += count;
            sender.send(ROTSenderOutput {
                id: this.sender_state.transfer_id,
                keys,
            });
        }
        this.keys.drain(..i);

        i = 0;
        for (count, sender) in mem::take(&mut this.receiver_state.queue) {
            let choices = this.choices[i..i + count].to_vec();
            let keys = this.msgs[i..i + count].to_vec();
            i += count;
            sender.send(ROTReceiverOutput {
                id: this.receiver_state.transfer_id,
                choices,
                msgs: keys,
            });
        }
        this.choices.drain(..i);
        this.msgs.drain(..i);

        Ok(())
    }
}

impl ROTSender<[Block; 2]> for IdealROT {
    type Error = IdealROTError;
    type Future = MaybeDone<ROTSenderOutput<[Block; 2]>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut this = self.inner.lock().unwrap();
        this.sender_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        let this = self.inner.lock().unwrap();
        this.keys.len()
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[Block; 2]>, Self::Error> {
        let mut this = self.inner.lock().unwrap();
        if this.keys.len() < count {
            return Err(IdealROTError::new(format!(
                "not enough ROTs available: {} < {}",
                this.keys.len(),
                count
            )));
        }

        let keys = this.keys.drain(..count).collect();
        Ok(ROTSenderOutput {
            id: this.sender_state.transfer_id.next(),
            keys,
        })
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let mut this = self.inner.lock().unwrap();
        let (sender, recv) = new_output();

        if this.keys.len() >= count {
            let keys = this.keys.drain(..count).collect();
            sender.send(ROTSenderOutput {
                id: this.sender_state.transfer_id.next(),
                keys,
            });
        } else {
            this.sender_state.queue.push((count, sender));
        }

        Ok(recv)
    }
}

impl ROTReceiver<bool, Block> for IdealROT {
    type Error = IdealROTError;
    type Future = MaybeDone<ROTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut this = self.inner.lock().unwrap();
        this.receiver_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        let this = self.inner.lock().unwrap();
        this.choices.len()
    }

    fn try_recv_rot(
        &mut self,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, Self::Error> {
        let mut this = self.inner.lock().unwrap();
        if this.choices.len() < count {
            return Err(IdealROTError::new(format!(
                "not enough ROTs available: {} < {}",
                this.choices.len(),
                count
            )));
        }

        let choices = this.choices.drain(..count).collect();
        let msgs = this.msgs.drain(..count).collect();
        Ok(ROTReceiverOutput {
            id: this.receiver_state.transfer_id.next(),
            choices,
            msgs,
        })
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let mut this = self.inner.lock().unwrap();
        let (sender, recv) = new_output();

        if this.choices.len() >= count {
            let choices = this.choices.drain(..count).collect();
            let keys = this.msgs.drain(..count).collect();
            sender.send(ROTReceiverOutput {
                id: this.receiver_state.transfer_id.next(),
                choices,
                msgs: keys,
            });
        } else {
            this.receiver_state.queue.push((count, sender));
        }

        Ok(recv)
    }
}

impl Default for IdealROT {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        Self::new(rng.gen())
    }
}

/// Error for [`IdealROT`].
#[derive(Debug, thiserror::Error)]
#[error("ideal ROT error: {0}")]
pub struct IdealROTError(String);

impl IdealROTError {
    fn new(msg: impl Into<String>) -> Self {
        IdealROTError(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::test::assert_rot;

    use super::*;

    #[test]
    fn test_ideal_rot() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let mut ideal = IdealROT::new(rng.gen());

        let count = 10;

        ROTSender::alloc(&mut ideal, count).unwrap();
        ROTReceiver::alloc(&mut ideal, count).unwrap();

        ideal.flush().unwrap();

        let (
            ROTSenderOutput {
                id: sender_id,
                keys,
            },
            ROTReceiverOutput {
                id: receiver_id,
                choices,
                msgs,
            },
        ) = ideal.transfer(count).unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_rot(&choices, &keys, &msgs);
    }
}
