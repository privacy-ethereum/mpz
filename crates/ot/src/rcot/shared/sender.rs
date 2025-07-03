use std::{
    collections::{HashMap, VecDeque},
    mem::take,
    sync::{Arc, Mutex as StdMutex},
};

use async_trait::async_trait;
use mpz_common::{
    Context, Flush,
    future::{MaybeDone, Sender, new_output},
    sync::AdaptiveBarrier,
};
use mpz_ot_core::{
    TransferId,
    rcot::{RCOTSender, RCOTSenderOutput},
};
use tokio::sync::Mutex;

#[derive(Debug)]
struct Buffer<U> {
    count: usize,
    keys: Vec<U>,
}

impl<U> Buffer<U> {
    fn new(count: usize) -> Self {
        Self {
            count,
            keys: Vec::with_capacity(count),
        }
    }
}

#[derive(Debug)]
struct State<U> {
    id_next: usize,
    alloc: usize,
    buffers: HashMap<usize, Buffer<U>>,
}

impl<U> State<U> {
    fn new() -> Self {
        Self {
            id_next: 0,
            alloc: 0,
            buffers: HashMap::new(),
        }
    }

    fn register(&mut self) -> usize {
        let id = self.id_next;
        self.id_next += 1;
        id
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
    barrier: AdaptiveBarrier,
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
    /// Creates a new shared RCOT sender.
    pub fn new(inner: T) -> Self {
        let delta = inner.delta();
        let inner = Arc::new(Mutex::new(inner));
        let barrier = AdaptiveBarrier::new();

        let mut state = State::new();
        let id = state.register();

        Self {
            id,
            transfer_id: TransferId::default(),
            inner: inner.clone(),
            barrier: barrier.clone(),
            state: Arc::new(StdMutex::new(state)),
            delta,
            keys: Vec::new(),
            queue: VecDeque::new(),
        }
    }
}

impl<T, U> Clone for SharedRCOTSender<T, U>
where
    U: Clone,
{
    fn clone(&self) -> Self {
        let mut state = self.state.lock().unwrap();
        let id = state.register();

        Self {
            id,
            transfer_id: TransferId::default(),
            inner: self.inner.clone(),
            barrier: self.barrier.clone(),
            state: self.state.clone(),
            delta: self.delta.clone(),
            keys: Vec::new(),
            queue: VecDeque::new(),
        }
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
        if count == 0 {
            return Ok(());
        }

        let mut state = self.state.lock().unwrap();

        state.alloc += count;

        if let Some(buffer) = state.buffers.get_mut(&self.id) {
            buffer.count += count;
            buffer.keys.reserve(count);
        } else {
            state.buffers.insert(self.id, Buffer::new(count));
        }

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

            Ok(recv)
        } else {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            Ok(recv)
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
        !self.state.lock().unwrap().buffers.is_empty()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        if !self.wants_flush() {
            return Ok(());
        }

        let barrier_result = self.barrier.wait().await;
        if barrier_result.is_leader() {
            let mut inner = self.inner.lock().await;

            {
                let state = self.state.lock().unwrap();
                for Buffer { count, .. } in state.buffers.values() {
                    inner.alloc(*count).map_err(SharedRCOTSenderError::inner)?;
                }
            }

            inner
                .flush(ctx)
                .await
                .map_err(SharedRCOTSenderError::inner)?;

            let state = &mut (*self.state.lock().unwrap());
            let mut buffers = state.buffers.iter_mut().collect::<Vec<_>>();
            buffers.sort_by_key(|(id, _)| *id);

            for (_, buffer) in buffers {
                let keys = inner
                    .try_send_rcot(buffer.count)
                    .map_err(SharedRCOTSenderError::inner)?
                    .keys;

                // Optimization: avoid expensive copying of `keys` potentially
                // containing millions of elements.
                let old_keys = std::mem::replace(&mut buffer.keys, keys);
                buffer.keys.extend_from_slice(&old_keys);
            }
        }
        barrier_result.proceed();

        {
            let mut state = self.state.lock().unwrap();
            if let Some(Buffer { keys, .. }) = state.buffers.remove(&self.id) {
                // Optimization: avoid expensive copying of `keys` potentially
                // containing millions of elements.
                let old_keys = std::mem::replace(&mut self.keys, keys);
                self.keys.extend_from_slice(&old_keys);
            }
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
