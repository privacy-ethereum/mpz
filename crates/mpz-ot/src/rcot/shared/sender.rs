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
    rcot::{RCOTSender, RCOTSenderOutput},
    TransferId,
};
use tokio::sync::{Barrier, Mutex};

#[derive(Debug)]
struct State<U> {
    allocs: Vec<usize>,
    keys: Vec<Vec<U>>,
}

impl<U> State<U> {
    fn new(n: usize) -> Self {
        Self {
            allocs: vec![0; n],
            keys: (0..n).map(|_| Vec::new()).collect(),
        }
    }
}

#[derive(Debug)]
struct Queued<U> {
    count: usize,
    sender: Sender<RCOTSenderOutput<U>>,
}

/// Shared RCOT sender.
#[derive(Debug)]
pub struct SharedRCOTSender<T, U> {
    id: usize,
    transfer_id: TransferId,
    inner: Arc<Mutex<T>>,
    barrier: Arc<Barrier>,
    state: Arc<StdMutex<State<U>>>,
    delta: U,
    keys: Vec<U>,
    queue: VecDeque<Queued<U>>,
}

impl<T, U> SharedRCOTSender<T, U>
where
    T: RCOTSender<U>,
    U: Copy + Send,
{
    /// Returns an iterator yielding `n` instances of `SharedRCOTSender`.
    pub fn new(n: usize, inner: T) -> impl Iterator<Item = Self> {
        let delta = inner.delta();
        let inner = Arc::new(Mutex::new(inner));
        let barrier = Arc::new(Barrier::new(n));
        let state = Arc::new(StdMutex::new(State::new(n)));

        (0..n).map(move |id| Self {
            id,
            transfer_id: TransferId::default(),
            inner: inner.clone(),
            barrier: barrier.clone(),
            state: state.clone(),
            delta,
            keys: Vec::new(),
            queue: VecDeque::new(),
        })
    }

    fn is_leader(&self) -> bool {
        self.id == 0
    }
}

impl<T, U> RCOTSender<U> for SharedRCOTSender<T, U>
where
    T: RCOTSender<U>,
    U: Copy + Send,
{
    type Error = SharedRCOTSenderError;
    type Future = MaybeDone<RCOTSenderOutput<U>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.state.lock().unwrap().allocs[self.id] += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.keys.len()
    }

    fn delta(&self) -> U {
        self.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<U>, Self::Error> {
        if self.available() < count {
            return Err(ErrorRepr::InsufficientSetup {
                expected: count,
                actual: self.available(),
            }
            .into());
        }

        let keys = self.keys.split_off(self.keys.len() - count);

        Ok(RCOTSenderOutput {
            id: self.transfer_id.next(),
            keys,
        })
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.available() >= count {
            let output = self.try_send_rcot(count)?;
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
impl<T, U> Flush for SharedRCOTSender<T, U>
where
    T: RCOTSender<U> + Flush + Send,
    U: Copy + Send,
{
    type Error = SharedRCOTSenderError;

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
                    inner.alloc(*alloc).map_err(SharedRCOTSenderError::inner)?;
                }
            }

            inner
                .flush(ctx)
                .await
                .map_err(SharedRCOTSenderError::inner)?;

            let state = &mut (*self.state.lock().unwrap());
            for (id, alloc) in state.allocs.iter_mut().enumerate() {
                let alloc = take(alloc);
                let keys = inner
                    .try_send_rcot(alloc)
                    .map_err(SharedRCOTSenderError::inner)?
                    .keys;
                state.keys[id].extend_from_slice(&keys);
            }
        }

        self.barrier.wait().await;

        {
            let mut state = self.state.lock().unwrap();
            self.keys.extend_from_slice(&state.keys[self.id]);
            state.keys[self.id].clear();
        }

        for queued in take(&mut self.queue) {
            let output = self.try_send_rcot(queued.count)?;
            queued.sender.send(output);
        }

        Ok(())
    }
}

/// Error for [`SharedRCOTSender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SharedRCOTSenderError(#[from] ErrorRepr);

impl SharedRCOTSenderError {
    fn inner<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Sender(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("shared RCOT sender error: ")]
enum ErrorRepr {
    #[error("inner sender error: {0}")]
    Sender(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("insufficient RCOTs setup: expected {expected}, actual {actual}")]
    InsufficientSetup { expected: usize, actual: usize },
}
