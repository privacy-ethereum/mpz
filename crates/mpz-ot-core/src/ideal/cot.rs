//! Ideal Correlated Oblivious Transfer functionality.

use std::{
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{new_output, MaybeDone, Output, Sender};
use mpz_core::Block;

use crate::{
    cot::{COTReceiver, COTReceiverOutput, COTSender, COTSenderOutput},
    TransferId,
};

type Error = IdealCOTError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Default)]
struct SenderState {
    alloc: usize,
    transfer_id: TransferId,
    queue: Vec<(usize, Sender<COTSenderOutput>)>,
}

#[derive(Debug, Default)]
struct ReceiverState {
    alloc: usize,
    transfer_id: TransferId,
    queue: Vec<(usize, Sender<COTReceiverOutput<Block>>)>,
}

/// Ideal COT functionality.
#[derive(Debug, Clone)]
pub struct IdealCOT {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    delta: Block,

    sender_state: SenderState,
    receiver_state: ReceiverState,

    keys: Vec<Block>,
    choices: Vec<bool>,
}

impl IdealCOT {
    /// Creates a new ideal COT functionality.
    ///
    /// # Arguments
    ///
    /// * `delta` - Global correlation key.
    pub fn new(delta: Block) -> Self {
        IdealCOT {
            inner: Arc::new(Mutex::new(Inner {
                delta,
                sender_state: SenderState::default(),
                receiver_state: ReceiverState::default(),
                keys: Vec::new(),
                choices: Vec::new(),
            })),
        }
    }

    /// Transfers correlated OTs.
    pub fn transfer(
        &mut self,
        choices: &[bool],
        keys: &[Block],
    ) -> Result<(COTSenderOutput, COTReceiverOutput<Block>)> {
        if choices.len() != keys.len() {
            return Err(Error::new(format!(
                "choices and keys length mismatch: {} != {}",
                choices.len(),
                keys.len()
            )));
        }

        let mut sender_output = self.queue_send_cot(keys)?;
        let mut receiver_output = self.queue_recv_cot(choices)?;

        self.flush()?;

        Ok((
            sender_output.try_recv().unwrap().unwrap(),
            receiver_output.try_recv().unwrap().unwrap(),
        ))
    }

    /// Returns `true` if the functionality wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        let this = self.inner.lock().unwrap();
        let sender_queue = this.sender_state.queue.len();
        let receiver_queue = this.receiver_state.queue.len();

        sender_queue > 0 || receiver_queue > 0
    }

    /// Flushes the functionality.
    pub fn flush(&mut self) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        if this.sender_state.alloc != this.receiver_state.alloc {
            return Err(Error::new(format!(
                "sender and receiver alloc out of sync: {} != {}",
                this.sender_state.alloc, this.receiver_state.alloc
            )));
        } else if this.keys.len() != this.choices.len() {
            return Err(Error::new(format!(
                "keys and choices length mismatch: {} != {}",
                this.keys.len(),
                this.choices.len()
            )));
        }

        this.sender_state.alloc = 0;
        this.receiver_state.alloc = 0;

        let keys = mem::take(&mut this.keys);
        let choices = mem::take(&mut this.choices);
        let sender_queue = mem::take(&mut this.sender_state.queue);
        let receiver_queue = mem::take(&mut this.receiver_state.queue);

        let delta = this.delta;
        let mut msgs = keys.into_iter().zip(choices).map(
            move |(key, choice)| {
                if choice {
                    key ^ delta
                } else {
                    key
                }
            },
        );

        for ((sender_count, sender_output), (receiver_count, receiver_output)) in
            sender_queue.into_iter().zip(receiver_queue.into_iter())
        {
            let sender_id = this.sender_state.transfer_id.next();
            let receiver_id = this.receiver_state.transfer_id.next();

            if sender_count != receiver_count {
                return Err(Error::new(format!("number of messages and choices do not match ({sender_id}): {sender_count} != {receiver_count}")));
            }

            sender_output.send(COTSenderOutput { id: sender_id });
            receiver_output.send(COTReceiverOutput {
                id: receiver_id,
                msgs: msgs.by_ref().take(receiver_count).collect(),
            });
        }

        Ok(())
    }
}

impl COTSender<Block> for IdealCOT {
    type Error = Error;
    type Future = MaybeDone<COTSenderOutput>;

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

    fn queue_send_cot(
        &mut self,
        keys: &[Block],
    ) -> Result<MaybeDone<COTSenderOutput>, Self::Error> {
        let mut this = self.inner.lock().unwrap();

        this.keys.extend_from_slice(keys);

        let (send, recv) = new_output();

        this.sender_state.queue.push((keys.len(), send));

        Ok(recv)
    }
}

impl COTReceiver<bool, Block> for IdealCOT {
    type Error = Error;
    type Future = MaybeDone<COTReceiverOutput<Block>>;

    fn alloc(&mut self, count: usize) -> Result<()> {
        let mut this = self.inner.lock().unwrap();
        this.receiver_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        let this = self.inner.lock().unwrap();
        this.choices.len()
    }

    fn queue_recv_cot(&mut self, choices: &[bool]) -> Result<MaybeDone<COTReceiverOutput<Block>>> {
        let mut this = self.inner.lock().unwrap();

        this.choices.extend_from_slice(choices);

        let (send, recv) = new_output();

        this.receiver_state.queue.push((choices.len(), send));

        Ok(recv)
    }
}

/// Error for [`IdealCOT`].
#[derive(Debug, thiserror::Error)]
#[error("ideal COT error: {0}")]
pub struct IdealCOTError(String);

impl IdealCOTError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    use crate::test::assert_cot;

    #[test]
    fn test_ideal_cot() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Block::random(&mut rng);
        let mut ideal = IdealCOT::new(delta);

        let count = 128;
        let choices = (0..count).map(|_| rng.gen()).collect::<Vec<_>>();
        let keys = (0..count).map(|_| rng.gen()).collect::<Vec<_>>();

        let (
            COTSenderOutput { id: sender_id },
            COTReceiverOutput {
                id: receiver_id,
                msgs: received,
            },
        ) = ideal.transfer(&choices, &keys).unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_cot(delta, &choices, &keys, &received)
    }
}
