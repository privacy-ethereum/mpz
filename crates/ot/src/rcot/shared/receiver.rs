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
    rcot::{RCOTReceiver, RCOTReceiverOutput},
};
use tokio::sync::Mutex;

#[derive(Debug)]
struct Buffer<U, V> {
    count: usize,
    inputs: Vec<U>,
    macs: Vec<V>,
}

impl<U, V> Buffer<U, V> {
    fn new(count: usize) -> Self {
        Self {
            count,
            inputs: Vec::with_capacity(count),
            macs: Vec::with_capacity(count),
        }
    }
}

#[derive(Debug)]
struct State<U, V> {
    id_next: usize,
    alloc: usize,
    buffers: HashMap<usize, Buffer<U, V>>,
}

impl<U, V> State<U, V> {
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
struct Queued<U, V> {
    count: usize,
    sender: Sender<RCOTReceiverOutput<U, V>>,
}

/// Shared RCOT receiver.
#[derive(Debug)]
pub struct SharedRCOTReceiver<T, U, V> {
    id: usize,
    transfer_id: TransferId,
    inner: Arc<Mutex<T>>,
    barrier: AdaptiveBarrier,
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
    /// Creates a new shared RCOT receiver.
    pub fn new(inner: T) -> Self {
        let inner = Arc::new(Mutex::new(inner));
        let barrier = AdaptiveBarrier::new();
        let mut state = State::new();
        let id = state.register();

        Self {
            id,
            transfer_id: TransferId::default(),
            inner,
            barrier,
            state: Arc::new(StdMutex::new(state)),
            inputs: Vec::new(),
            macs: Vec::new(),
            queue: VecDeque::new(),
        }
    }
}

impl<T, U, V> Clone for SharedRCOTReceiver<T, U, V>
where
    U: Copy + Send,
    V: Copy + Send,
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
            inputs: Vec::new(),
            macs: Vec::new(),
            queue: VecDeque::new(),
        }
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
        let mut state = self.state.lock().unwrap();

        state.alloc += count;

        if let Some(buffer) = state.buffers.get_mut(&self.id) {
            buffer.count += count;
            buffer.inputs.reserve(count);
            buffer.macs.reserve(count);
        } else {
            state.buffers.insert(self.id, Buffer::new(count));
        }

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

            Ok(recv)
        } else {
            let (sender, recv) = new_output();

            self.queue.push_back(Queued { count, sender });

            Ok(recv)
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
                for buffer in state.buffers.values() {
                    inner
                        .alloc(buffer.count)
                        .map_err(SharedRCOTReceiverError::inner)?;
                }
            }

            inner
                .flush(ctx)
                .await
                .map_err(SharedRCOTReceiverError::inner)?;

            let state = &mut (*self.state.lock().unwrap());
            let mut buffers = state.buffers.iter_mut().collect::<Vec<_>>();
            buffers.sort_by_key(|(id, _)| *id);

            for (_, buffer) in buffers {
                let output = inner
                    .try_recv_rcot(buffer.count)
                    .map_err(SharedRCOTReceiverError::inner)?;

                buffer.inputs.extend_from_slice(&output.choices);
                buffer.macs.extend_from_slice(&output.msgs);
            }
        }
        barrier_result.proceed();

        {
            let mut state = self.state.lock().unwrap();
            if let Some(buffer) = state.buffers.remove(&self.id) {
                self.inputs.extend_from_slice(&buffer.inputs);
                self.macs.extend_from_slice(&buffer.macs);
            }
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
