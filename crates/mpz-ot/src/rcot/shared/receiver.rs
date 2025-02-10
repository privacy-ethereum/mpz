use std::{
    collections::VecDeque,
    mem::take,
    sync::{Arc, Mutex as StdMutex},
};

use async_trait::async_trait;
use mpz_common::{
    future::{new_output, MaybeDone, Sender},
    Context, Flush,
};
use mpz_ot_core::{
    rcot::{RCOTReceiver, RCOTReceiverOutput},
    TransferId,
};
use tokio::sync::{Barrier, Mutex};

#[derive(Debug)]
struct State<U, V> {
    allocs: Vec<usize>,
    inputs: Vec<Vec<U>>,
    macs: Vec<Vec<V>>,
}

impl<U, V> State<U, V> {
    fn new(n: usize) -> Self {
        Self {
            allocs: vec![0; n],
            inputs: (0..n).map(|_| Vec::new()).collect(),
            macs: (0..n).map(|_| Vec::new()).collect(),
        }
    }
}

#[derive(Debug)]
struct Queued<U, V> {
    count: usize,
    sender: Sender<RCOTReceiverOutput<U, V>>,
}

/// Shared RCOT recver.
#[derive(Debug)]
pub struct SharedRCOTReceiver<T, U, V> {
    id: usize,
    transfer_id: TransferId,
    inner: Arc<Mutex<T>>,
    barrier: Arc<Barrier>,
    state: Arc<StdMutex<State<U, V>>>,
    inputs: Vec<U>,
    macs: Vec<V>,
    queue: VecDeque<Queued<U, V>>,
}

impl<T, U, V> SharedRCOTReceiver<T, U, V>
where
    T: RCOTReceiver<U, V>,
    U: Copy + Send,
    V: Copy + Send,
{
    /// Returns an iterator yielding `n` instances of `SharedRCOTReceiver`.
    pub fn new(n: usize, inner: T) -> impl Iterator<Item = Self> {
        let inner = Arc::new(Mutex::new(inner));
        let barrier = Arc::new(Barrier::new(n));
        let state = Arc::new(StdMutex::new(State::new(n)));

        (0..n).map(move |id| Self {
            id,
            transfer_id: TransferId::default(),
            inner: inner.clone(),
            barrier: barrier.clone(),
            state: state.clone(),
            inputs: Vec::new(),
            macs: Vec::new(),
            queue: VecDeque::new(),
        })
    }

    fn is_leader(&self) -> bool {
        self.id == 0
    }
}

impl<T, U, V> RCOTReceiver<U, V> for SharedRCOTReceiver<T, U, V>
where
    T: RCOTReceiver<U, V>,
    U: Copy + Send,
    V: Copy + Send,
{
    type Error = SharedRCOTReceiverError;
    type Future = MaybeDone<RCOTReceiverOutput<U, V>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.state.lock().unwrap().allocs[self.id] += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.macs.len()
    }

    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<U, V>, Self::Error> {
        if self.available() < count {
            return Err(ErrorRepr::InsufficientSetup {
                expected: count,
                actual: self.available(),
            }
            .into());
        }

        let inputs = self.inputs.split_off(self.inputs.len() - count);
        let macs = self.macs.split_off(self.macs.len() - count);

        Ok(RCOTReceiverOutput {
            id: self.transfer_id.next(),
            choices: inputs,
            msgs: macs,
        })
    }

    fn queue_recv_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.available() >= count {
            let output = self.try_recv_rcot(count)?;
            let (sender, recv) = new_output();
            sender.send(output);

            return Ok(recv);
        } else {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            return Ok(recv);
        }
    }
}

#[async_trait]
impl<T, U, V> Flush for SharedRCOTReceiver<T, U, V>
where
    T: RCOTReceiver<U, V> + Flush + Send,
    U: Copy + Send,
    V: Copy + Send,
{
    type Error = SharedRCOTReceiverError;

    fn wants_flush(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .allocs
            .iter()
            .any(|&alloc| alloc > 0)
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        self.barrier.wait().await;

        if self.is_leader() {
            let mut inner = self.inner.lock().await;

            {
                let state = self.state.lock().unwrap();
                for alloc in state.allocs.iter() {
                    inner
                        .alloc(*alloc)
                        .map_err(SharedRCOTReceiverError::inner)?;
                }
            }

            inner
                .flush(ctx)
                .await
                .map_err(SharedRCOTReceiverError::inner)?;

            let state = &mut (*self.state.lock().unwrap());
            for (id, alloc) in state.allocs.iter_mut().enumerate() {
                let alloc = take(alloc);
                let output = inner
                    .try_recv_rcot(alloc)
                    .map_err(SharedRCOTReceiverError::inner)?;

                state.inputs[id].extend_from_slice(&output.choices);
                state.macs[id].extend_from_slice(&output.msgs);
            }
        }

        self.barrier.wait().await;

        {
            let mut state = self.state.lock().unwrap();
            self.inputs.extend_from_slice(&state.inputs[self.id]);
            self.macs.extend_from_slice(&state.macs[self.id]);
            state.inputs[self.id].clear();
            state.macs[self.id].clear();
        }

        for queued in take(&mut self.queue) {
            let output = self.try_recv_rcot(queued.count)?;
            queued.sender.send(output);
        }

        Ok(())
    }
}

/// Error for [`SharedRCOTReceiver`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SharedRCOTReceiverError(#[from] ErrorRepr);

impl SharedRCOTReceiverError {
    fn inner<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Receiver(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("shared RCOT receiver error: ")]
enum ErrorRepr {
    #[error("inner receiver error: {0}")]
    Receiver(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("insufficient RCOTs setup: expected {expected}, actual {actual}")]
    InsufficientSetup { expected: usize, actual: usize },
}
