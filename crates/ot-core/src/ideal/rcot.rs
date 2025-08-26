//! Ideal Random Correlated Oblivious Transfer functionality.

use std::{
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_core::{Block, prg::Prg};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    TransferId,
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};

type Error = IdealRCOTError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Default)]
struct SenderState {
    alloc: usize,
    transfer_id: TransferId,
    queue: Vec<(usize, Sender<RCOTSenderOutput<Block>>)>,
}

#[derive(Debug, Default)]
struct ReceiverState {
    alloc: usize,
    transfer_id: TransferId,
    queue: Vec<(usize, Sender<RCOTReceiverOutput<bool, Block>>)>,
}

/// Ideal RCOT functionality.
#[derive(Debug, Clone)]
pub struct IdealRCOT {
    inner: Inner,
}

#[derive(Debug, Clone)]
struct Inner {
    delta: Block,
    prg: Prg,

    sender_state: Arc<Mutex<SenderState>>,
    receiver_state: Arc<Mutex<ReceiverState>>,

    keys: Arc<Mutex<Vec<Block>>>,
    msgs: Arc<Mutex<Vec<Block>>>,
    choices: Arc<Mutex<Vec<bool>>>,
}

impl IdealRCOT {
    /// Creates a new ideal RCOT functionality.
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed for the PRG.
    /// * `delta` - Global correlation key.
    pub fn new(seed: Block, delta: Block) -> Self {
        IdealRCOT {
            inner: Inner {
                delta,
                prg: Prg::from_seed(seed),
                sender_state: Arc::new(Mutex::new(SenderState::default())),
                receiver_state: Arc::new(Mutex::new(ReceiverState::default())),
                keys: Arc::new(Mutex::new(Vec::new())),
                msgs: Arc::new(Mutex::new(Vec::new())),
                choices: Arc::new(Mutex::new(Vec::new())),
            },
        }
    }

    /// Allocates `count` random correlated OTs.
    pub fn alloc(&mut self, count: usize) {
        self.inner.sender_state.try_lock().unwrap().alloc += count;
        self.inner.receiver_state.try_lock().unwrap().alloc += count;
    }

    /// Transfers `count` random correlated OTs.
    pub fn transfer(
        &mut self,
        count: usize,
    ) -> Result<(RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>)> {
        Ok((self.try_send_rcot(count)?, self.try_recv_rcot(count)?))
    }

    /// Returns `true` if the sender wants to be flushed.
    pub fn sender_wants_flush(&self) -> bool {
        self.inner.sender_state.try_lock().unwrap().alloc > 0
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn receiver_wants_flush(&self) -> bool {
        self.inner.receiver_state.try_lock().unwrap().alloc > 0
    }

    /// Flushes pending operations.
    pub fn flush(&mut self) -> Result<()> {
        // It is safe to hold the locks for the duration of the flush, since
        // only one party is executing the flush while the other is waiting
        // at the barrier.
        let mut sender_state = self.inner.sender_state.try_lock().unwrap();
        let mut receiver_state = self.inner.receiver_state.try_lock().unwrap();
        let mut keys_guard = self.inner.keys.try_lock().unwrap();
        let mut choices_guard = self.inner.choices.try_lock().unwrap();
        let mut msgs_guard = self.inner.msgs.try_lock().unwrap();

        if sender_state.alloc != receiver_state.alloc {
            return Err(Error::new(format!(
                "sender and receiver alloc out of sync: {} != {}",
                sender_state.alloc, receiver_state.alloc
            )));
        }

        let count = sender_state.alloc;

        let keys = (0..count)
            .map(|_| self.inner.prg.random())
            .collect::<Vec<_>>();
        let choices = (0..count)
            .map(|_| self.inner.prg.random())
            .collect::<Vec<_>>();
        let msgs = keys
            .iter()
            .zip(&choices)
            .map(|(key, choice)| {
                if *choice {
                    *key ^ self.inner.delta
                } else {
                    *key
                }
            })
            .collect::<Vec<_>>();

        keys_guard.extend_from_slice(&keys);
        choices_guard.extend_from_slice(&choices);
        msgs_guard.extend_from_slice(&msgs);

        sender_state.alloc = 0;
        receiver_state.alloc = 0;

        let mut keys_len = keys_guard.len();
        for (count, sender) in mem::take(&mut sender_state.queue) {
            let split_keys = keys_guard.split_off(keys_len - count);
            keys_len -= count;
            sender.send(RCOTSenderOutput {
                id: sender_state.transfer_id.next(),
                keys: split_keys,
            });
        }

        let mut choices_len = choices_guard.len();
        for (count, sender) in mem::take(&mut receiver_state.queue) {
            let split_choices = choices_guard.split_off(choices_len - count);
            let split_msgs = msgs_guard.split_off(choices_len - count);
            choices_len -= count;
            sender.send(RCOTReceiverOutput {
                id: receiver_state.transfer_id.next(),
                choices: split_choices,
                msgs: split_msgs,
            });
        }

        Ok(())
    }
}

impl RCOTSender<Block> for IdealRCOT {
    type Error = Error;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        self.inner.sender_state.try_lock().unwrap().alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.inner.keys.try_lock().unwrap().len()
    }

    fn delta(&self) -> Block {
        self.inner.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>> {
        let mut sender_state = self.inner.sender_state.try_lock().unwrap();
        let mut keys = self.inner.keys.try_lock().unwrap();
        let keys_len: usize = keys.len();

        if count > keys_len {
            return Err(Error::new(format!(
                "not enough sender RCOTs available: {keys_len} < {count}"
            )));
        }

        let id = sender_state.transfer_id.next();
        let split_keys = keys.split_off(keys_len - count);

        Ok(RCOTSenderOutput {
            id,
            keys: split_keys,
        })
    }

    fn queue_send_rcot(
        &mut self,
        count: usize,
    ) -> Result<MaybeDone<RCOTSenderOutput<Block>>, Self::Error> {
        let mut sender_state = self.inner.sender_state.try_lock().unwrap();
        let mut keys = self.inner.keys.try_lock().unwrap();
        let keys_len: usize = keys.len();

        let (send, recv) = new_output();

        let available = keys_len;
        if available >= count {
            let id = sender_state.transfer_id.next();
            let split_keys = keys.split_off(keys_len - count);

            send.send(RCOTSenderOutput {
                id,
                keys: split_keys,
            });
        } else {
            sender_state.queue.push((count, send));
        }

        Ok(recv)
    }
}

impl RCOTReceiver<bool, Block> for IdealRCOT {
    type Error = Error;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        self.inner.receiver_state.try_lock().unwrap().alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.inner.choices.try_lock().unwrap().len()
    }

    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<bool, Block>> {
        let mut receiver_state = self.inner.receiver_state.try_lock().unwrap();
        let mut choices = self.inner.choices.try_lock().unwrap();
        let mut msgs = self.inner.msgs.try_lock().unwrap();
        // choices and msgs are the same length.
        let choices_len = choices.len();

        if count > choices_len {
            return Err(Error::new(format!(
                "not enough receiver RCOTs available: {choices_len} < {count}"
            )));
        }

        let split_choices = choices.split_off(choices_len - count);
        let split_msgs = msgs.split_off(choices_len - count);

        Ok(RCOTReceiverOutput {
            id: receiver_state.transfer_id.next(),
            choices: split_choices,
            msgs: split_msgs,
        })
    }

    fn queue_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<MaybeDone<RCOTReceiverOutput<bool, Block>>> {
        let mut receiver_state = self.inner.receiver_state.try_lock().unwrap();
        let mut choices = self.inner.choices.try_lock().unwrap();
        let mut msgs = self.inner.msgs.try_lock().unwrap();
        // choices and msgs are the same length.
        let choices_len = choices.len();

        let (send, recv) = new_output();

        let available = choices_len;
        if available >= count {
            let id = receiver_state.transfer_id.next();
            let split_choices = choices.split_off(choices_len - count);
            let split_msgs = msgs.split_off(choices_len - count);

            send.send(RCOTReceiverOutput {
                id,
                choices: split_choices,
                msgs: split_msgs,
            });
        } else {
            receiver_state.queue.push((count, send));
        }

        Ok(recv)
    }
}

impl Default for IdealRCOT {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        Self::new(rng.random(), rng.random())
    }
}

/// Error for [`IdealRCOT`].
#[derive(Debug, thiserror::Error)]
#[error("ideal RCOT error: {0}")]
pub struct IdealRCOTError(String);

impl IdealRCOTError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::assert_cot;

    #[test]
    fn test_ideal_rcot() {
        let mut ideal = IdealRCOT::default();

        ideal.alloc(100);
        ideal.flush().unwrap();

        let (
            RCOTSenderOutput { keys: msgs, .. },
            RCOTReceiverOutput {
                choices,
                msgs: received,
                ..
            },
        ) = ideal.transfer(100).unwrap();

        assert_cot(ideal.delta(), &choices, &msgs, &received)
    }
}
