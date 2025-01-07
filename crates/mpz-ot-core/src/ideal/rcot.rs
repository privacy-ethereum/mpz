//! Ideal Random Correlated Oblivious Transfer functionality.

use std::{
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{new_output, MaybeDone, Sender};
use mpz_core::{prg::Prg, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
    TransferId,
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
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    delta: Block,
    prg: Prg,

    sender_state: SenderState,
    receiver_state: ReceiverState,

    keys: Vec<Block>,
    msgs: Vec<Block>,
    choices: Vec<bool>,
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
            inner: Arc::new(Mutex::new(Inner {
                delta,
                prg: Prg::from_seed(seed),
                sender_state: SenderState::default(),
                receiver_state: ReceiverState::default(),
                keys: Vec::new(),
                msgs: Vec::new(),
                choices: Vec::new(),
            })),
        }
    }

    /// Allocates `count` random correlated OTs.
    pub fn alloc(&mut self, count: usize) {
        let mut this = self.inner.lock().unwrap();
        this.sender_state.alloc += count;
        this.receiver_state.alloc += count;
    }

    /// Transfers `count` random correlated OTs.
    pub fn transfer(
        &mut self,
        count: usize,
    ) -> Result<(RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>)> {
        Ok((self.try_send_rcot(count)?, self.try_recv_rcot(count)?))
    }

    /// Returns `true` if the functionality wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        let this = self.inner.lock().unwrap();
        let sender_count = this.sender_state.alloc;
        let receiver_count = this.receiver_state.alloc;

        sender_count > 0 || receiver_count > 0
    }

    /// Flushes pending operations.
    pub fn flush(&mut self) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        if this.sender_state.alloc != this.receiver_state.alloc {
            return Err(Error::new(format!(
                "sender and receiver alloc out of sync: {} != {}",
                this.sender_state.alloc, this.receiver_state.alloc
            )));
        }

        let count = this.sender_state.alloc;

        let keys = (0..count).map(|_| this.prg.gen()).collect::<Vec<_>>();
        let choices = (0..count).map(|_| this.prg.gen()).collect::<Vec<_>>();
        let msgs = keys
            .iter()
            .zip(&choices)
            .map(|(key, choice)| if *choice { *key ^ this.delta } else { *key })
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
            sender.send(RCOTSenderOutput {
                id: this.sender_state.transfer_id.next(),
                keys,
            });
        }
        this.keys.drain(..i);

        i = 0;
        for (count, sender) in mem::take(&mut this.receiver_state.queue) {
            let choices = this.choices[i..i + count].to_vec();
            let keys = this.msgs[i..i + count].to_vec();
            i += count;
            sender.send(RCOTReceiverOutput {
                id: this.receiver_state.transfer_id.next(),
                choices,
                msgs: keys,
            });
        }
        this.choices.drain(..i);
        this.msgs.drain(..i);

        Ok(())
    }
}

impl RCOTSender<Block> for IdealRCOT {
    type Error = Error;
    type Future = MaybeDone<RCOTSenderOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        this.sender_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        let this = self.inner.lock().unwrap();
        this.keys.len()
    }

    fn delta(&self) -> Block {
        let this = self.inner.lock().unwrap();
        this.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>> {
        let mut this = self.inner.lock().unwrap();
        if count > this.keys.len() {
            return Err(Error::new(format!(
                "not enough sender RCOTs available: {} < {}",
                this.keys.len(),
                count
            )));
        }

        let id = this.sender_state.transfer_id.next();
        let keys = this.keys.drain(..count).collect();

        Ok(RCOTSenderOutput { id, keys })
    }

    fn queue_send_rcot(
        &mut self,
        count: usize,
    ) -> Result<MaybeDone<RCOTSenderOutput<Block>>, Self::Error> {
        let mut this = self.inner.lock().unwrap();
        let (send, recv) = new_output();

        let available = this.keys.len();
        if available >= count {
            let id = this.sender_state.transfer_id.next();
            let keys = this.keys.drain(..count).collect();

            send.send(RCOTSenderOutput { id, keys });
        } else {
            this.sender_state.queue.push((count, send));
        }

        Ok(recv)
    }
}

impl RCOTReceiver<bool, Block> for IdealRCOT {
    type Error = Error;
    type Future = MaybeDone<RCOTReceiverOutput<bool, Block>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        this.receiver_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        let this = self.inner.lock().unwrap();
        this.choices.len()
    }

    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<bool, Block>> {
        let mut this = self.inner.lock().unwrap();
        if count > this.choices.len() {
            return Err(Error::new(format!(
                "not enough receiver RCOTs available: {} < {}",
                this.choices.len(),
                count
            )));
        }

        let choices = this.choices.drain(..count).collect();
        let msgs = this.msgs.drain(..count).collect();

        Ok(RCOTReceiverOutput {
            id: this.receiver_state.transfer_id.next(),
            choices,
            msgs,
        })
    }

    fn queue_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<MaybeDone<RCOTReceiverOutput<bool, Block>>> {
        let mut this = self.inner.lock().unwrap();
        let (send, recv) = new_output();

        let available = this.choices.len();
        if available >= count {
            let id = this.receiver_state.transfer_id.next();
            let choices = this.choices.drain(..count).collect();
            let msgs = this.msgs.drain(..count).collect();

            send.send(RCOTReceiverOutput { id, choices, msgs });
        } else {
            this.receiver_state.queue.push((count, send));
        }

        Ok(recv)
    }
}

impl Default for IdealRCOT {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        Self::new(rng.gen(), rng.gen())
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
