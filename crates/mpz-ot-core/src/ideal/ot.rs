//! Ideal Chosen-Message Oblivious Transfer functionality.

use std::{
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{new_output, MaybeDone, Output, Sender};
use mpz_core::Block;

use crate::{
    ot::{OTReceiver, OTReceiverOutput, OTSender, OTSenderOutput},
    TransferId,
};

#[derive(Debug, Default)]
struct SenderState {
    transfer_id: TransferId,
    queue: Vec<(usize, Sender<OTSenderOutput>)>,
}

#[derive(Debug, Default)]
struct ReceiverState {
    transfer_id: TransferId,
    queue: Vec<(usize, Sender<OTReceiverOutput<Block>>)>,
}

/// The ideal OT functionality.
#[derive(Debug, Default, Clone)]
pub struct IdealOT {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    sender_state: SenderState,
    receiver_state: ReceiverState,

    msgs: Vec<[Block; 2]>,
    choices: Vec<bool>,
}

impl IdealOT {
    /// Creates a new ideal OT functionality.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the functionality wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        let this = self.inner.lock().unwrap();
        let sender_queue = this.sender_state.queue.len();
        let receiver_queue = this.receiver_state.queue.len();

        sender_queue > 0 && receiver_queue > 0 && sender_queue == receiver_queue
    }

    /// Flushes the functionality.
    pub fn flush(&mut self) -> Result<(), IdealOTError> {
        let mut this = self.inner.lock().unwrap();

        if this.msgs.len() != this.choices.len() {
            return Err(IdealOTError::new(
                "number of messages and choices do not match",
            ));
        }

        let sender_queue = mem::take(&mut this.sender_state.queue);
        let receiver_queue = mem::take(&mut this.receiver_state.queue);
        let msgs = mem::take(&mut this.msgs);
        let choices = mem::take(&mut this.choices);

        let mut msgs = msgs
            .into_iter()
            .zip(choices)
            .map(|([zero, one], choice)| if choice { one } else { zero });

        for ((sender_count, sender_output), (receiver_count, receiver_output)) in
            sender_queue.into_iter().zip(receiver_queue)
        {
            let sender_id = this.sender_state.transfer_id.next();
            let receiver_id = this.receiver_state.transfer_id.next();

            if sender_count != receiver_count {
                return Err(IdealOTError::new(format!("number of messages and choices do not match ({sender_id}): {sender_count} != {receiver_count}")));
            }

            sender_output.send(OTSenderOutput { id: sender_id });
            receiver_output.send(OTReceiverOutput {
                id: receiver_id,
                msgs: msgs.by_ref().take(sender_count).collect(),
            });
        }

        Ok(())
    }

    /// Executes chosen-message oblivious transfers.
    ///
    /// # Arguments
    ///
    /// * `choices` - The choices made by the receiver.
    /// * `msgs` - The sender's messages.
    pub fn transfer(
        &mut self,
        choices: &[bool],
        msgs: &[[Block; 2]],
    ) -> Result<(OTSenderOutput, OTReceiverOutput<Block>), IdealOTError> {
        let mut sender_output = self.queue_send_ot(msgs)?;
        let mut receiver_output = self.queue_recv_ot(choices)?;

        self.flush()?;

        Ok((
            sender_output.try_recv().unwrap().unwrap(),
            receiver_output.try_recv().unwrap().unwrap(),
        ))
    }
}

impl OTSender<Block> for IdealOT {
    type Error = IdealOTError;
    type Future = MaybeDone<OTSenderOutput>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn queue_send_ot(&mut self, msgs: &[[Block; 2]]) -> Result<Self::Future, Self::Error> {
        let mut this = self.inner.lock().unwrap();
        this.msgs.extend_from_slice(msgs);

        let (sender, recv) = new_output();

        this.sender_state.queue.push((msgs.len(), sender));

        Ok(recv)
    }
}

impl OTReceiver<bool, Block> for IdealOT {
    type Error = IdealOTError;
    type Future = MaybeDone<OTReceiverOutput<Block>>;

    fn alloc(&mut self, _count: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn queue_recv_ot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        let mut this = self.inner.lock().unwrap();
        this.choices.extend_from_slice(choices);

        let (sender, recv) = new_output();

        this.receiver_state.queue.push((choices.len(), sender));

        Ok(recv)
    }
}

/// Error for [`IdealOT`].
#[derive(Debug, thiserror::Error)]
#[error("Ideal OT error: {0}")]
pub struct IdealOTError(String);

impl IdealOTError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use mpz_core::Block;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use crate::test::assert_ot;

    use super::*;

    #[test]
    fn test_ideal_ot() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut choices = vec![false; 100];
        rng.fill(&mut choices[..]);

        let msgs: Vec<[Block; 2]> = (0..100).map(|_| [rng.gen(), rng.gen()]).collect();

        let (OTSenderOutput { .. }, OTReceiverOutput { msgs: chosen, .. }) =
            IdealOT::default().transfer(&choices, &msgs).unwrap();

        assert_ot(&choices, &msgs, &chosen);
    }
}
