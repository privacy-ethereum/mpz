mod builder;
pub(crate) mod pool;
mod spawn;
mod worker;

use std::sync::{Arc, Mutex};

use futures::{StreamExt as _, stream::FuturesUnordered};
use worker::Handle;

use crate::{
    Context, ContextError, ThreadId, context::ErrorKind, load_balance::distribute_by_weight,
    mux::Mux,
};

use async_executor::LocalExecutor;
use pool::{SharedPool, TaskFn, TaskSenders};

pub use builder::{MultithreadBuilder, MultithreadBuilderError};
pub use spawn::{CustomSpawn, Spawn, SpawnError, StdSpawn};

#[derive(Debug)]
pub(crate) struct MtConfig {
    concurrency: usize,
}

/// A multi-threaded context.
pub struct Multithread {
    current_id: ThreadId,
    config: Arc<MtConfig>,
    builder: Arc<Mutex<ThreadBuilder>>,
    senders: TaskSenders,
    // Held to keep pool workers alive; dropping shuts them down.
    _pool: SharedPool,
}

impl std::fmt::Debug for Multithread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Multithread")
            .field("current_id", &self.current_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Multithread {
    /// Creates a new builder.
    pub fn builder() -> MultithreadBuilder {
        MultithreadBuilder::default()
    }

    /// Creates a new multi-threaded context.
    pub fn new_context(&mut self) -> Result<Context, ContextError> {
        let id = self.current_id.increment().ok_or_else(|| {
            ContextError::new(ErrorKind::Thread, "thread ID overflow".to_string())
        })?;

        let io = self
            .builder
            .lock()
            .unwrap()
            .mux
            .open(id.clone())
            .map_err(|e| ContextError::new(ErrorKind::Mux, e))?;

        let ctx = Context::new_multi_threaded(
            id.clone(),
            io,
            self.config.clone(),
            self.builder.clone(),
            self.senders.clone(),
        );

        Ok(ctx)
    }
}

pub(crate) struct ThreadBuilder {
    mux: Box<dyn Mux + Send>,
}

impl std::fmt::Debug for ThreadBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadBuilder").finish_non_exhaustive()
    }
}

pub(crate) struct Threads {
    config: Arc<MtConfig>,
    builder: Arc<Mutex<ThreadBuilder>>,
    senders: TaskSenders,
    child_id: ThreadId,
    children: Vec<Handle>,
}

impl std::fmt::Debug for Threads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Threads")
            .field("child_id", &self.child_id)
            .field("children", &self.children)
            .finish_non_exhaustive()
    }
}

impl Threads {
    pub(crate) fn new(
        parent_id: ThreadId,
        config: Arc<MtConfig>,
        builder: Arc<Mutex<ThreadBuilder>>,
        senders: TaskSenders,
    ) -> Self {
        Self {
            config,
            builder,
            senders,
            child_id: parent_id.fork(),
            children: Vec::new(),
        }
    }

    pub(crate) fn concurrency(&self) -> usize {
        self.config.concurrency
    }

    /// Returns handles for `count` logical worker threads.
    ///
    /// Each handle is assigned to a pool thread via round-robin.
    pub(crate) fn get(&mut self, count: usize) -> Result<&[Handle], ContextError> {
        if count > self.config.concurrency {
            return Err(ContextError::new(
                ErrorKind::Thread,
                "requested more threads than available".to_string(),
            ));
        } else if self.children.len() < count {
            let diff = count - self.children.len();
            for _ in 0..diff {
                let id = self.child_id.increment_in_place().ok_or_else(|| {
                    ContextError::new(ErrorKind::Thread, "thread ID overflow".to_string())
                })?;

                let io = self
                    .builder
                    .lock()
                    .unwrap()
                    .mux
                    .open(id.clone())
                    .map_err(|e| ContextError::new(ErrorKind::Mux, e))?;

                let ctx = Context::new_multi_threaded(
                    id.clone(),
                    io,
                    self.config.clone(),
                    self.builder.clone(),
                    self.senders.clone(),
                );

                // Assign to pool thread round-robin.
                let sender_idx = self.children.len() % self.senders.len();
                let sender = self.senders[sender_idx].clone();

                self.children.push(Handle::new(id, ctx, sender));
            }
        }

        Ok(&self.children[..count])
    }
}

/// Dispatches an async closure to a pool thread and returns a receiver for
/// the result.
///
/// The closure is `Send` and crosses the thread boundary. The future it
/// produces runs on the pool thread's `LocalExecutor` and does NOT need to
/// be `Send`.
fn spawn_task<A, R>(
    sender: &async_channel::Sender<TaskFn>,
    ctx: Context,
    a: A,
) -> Result<async_channel::Receiver<(R, Context)>, ContextError>
where
    A: AsyncFnOnce(&mut Context) -> R + Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = async_channel::bounded(1);
    // Closure is Send (captures Send types). It spawns on the pool thread's
    // LocalExecutor directly — no extra boxing needed.
    sender
        .try_send(Box::new(move |ex: &LocalExecutor<'_>| {
            ex.spawn(async move {
                let mut ctx = ctx;
                let r = a(&mut ctx).await;
                let _ = tx.send((r, ctx)).await;
            })
            .detach();
        }))
        .map_err(|_| send_error())?;
    Ok(rx)
}

fn send_error() -> ContextError {
    ContextError::new(
        ErrorKind::Thread,
        "failed to dispatch task: pool thread channel closed".to_string(),
    )
}

fn recv_error() -> ContextError {
    ContextError::new(
        ErrorKind::Thread,
        "pool thread dropped task before completion".to_string(),
    )
}

pub(crate) async fn map<F, T, R, W>(
    threads: &[Handle],
    items: Vec<T>,
    f: F,
    weight: W,
) -> Result<Vec<R>, ContextError>
where
    F: for<'b> AsyncFn(&'b mut Context, T) -> R + Clone + Send + 'static,
    T: Send + 'static,
    R: Send + 'static,
    W: Fn(&T) -> usize + Send + 'static,
{
    let items = items.into_iter().enumerate().collect::<Vec<_>>();
    let item_count = items.len();
    let lanes = distribute_by_weight(items, |item| weight(&item.1), threads.len());

    let mut tasks = Vec::new();
    for (i, (lane, thread)) in lanes.into_iter().zip(threads.iter()).enumerate() {
        let f = f.clone();
        let ctx = thread.take_ctx()?;
        let (tx, rx) = async_channel::bounded(1);

        thread
            .sender()
            .try_send(Box::new(move |ex: &LocalExecutor<'_>| {
                ex.spawn(async move {
                    let mut ctx = ctx;
                    let mut results = Vec::with_capacity(lane.len());
                    for (idx, item) in lane {
                        results.push((idx, f(&mut ctx, item).await));
                    }
                    let _ = tx.send((results, ctx)).await;
                })
                .detach();
            }))
            .map_err(|_| send_error())?;

        tasks.push((i, rx));
    }

    let mut queue = FuturesUnordered::new();
    for (i, rx) in tasks {
        queue.push(async move { (i, rx.recv().await) });
    }

    let mut outputs = Vec::with_capacity(item_count);
    while let Some((thread_idx, result)) = queue.next().await {
        let (lane, ctx) = result.map_err(|_| recv_error())?;
        threads[thread_idx].put_ctx(ctx);
        outputs.extend(lane);
    }

    outputs.sort_by_key(|(i, _)| *i);

    Ok(outputs.into_iter().map(|(_, output)| output).collect())
}

pub(crate) async fn join<A, B, RA, RB>(
    threads: &[Handle],
    a: A,
    b: B,
) -> Result<(RA, RB), ContextError>
where
    A: for<'b> AsyncFnOnce(&'b mut Context) -> RA + Send + 'static,
    B: for<'b> AsyncFnOnce(&'b mut Context) -> RB + Send + 'static,
    RA: Send + 'static,
    RB: Send + 'static,
{
    assert_eq!(threads.len(), 2, "expecting exactly two threads");

    let ctx_a = threads[0].take_ctx()?;
    let ctx_b = threads[1].take_ctx()?;

    let rx_a = spawn_task(threads[0].sender(), ctx_a, a)?;
    let rx_b = spawn_task(threads[1].sender(), ctx_b, b)?;

    let (ra, ctx_a) = rx_a.recv().await.map_err(|_| recv_error())?;
    let (rb, ctx_b) = rx_b.recv().await.map_err(|_| recv_error())?;

    threads[0].put_ctx(ctx_a);
    threads[1].put_ctx(ctx_b);

    Ok((ra, rb))
}

pub(crate) async fn try_join<A, B, RA, RB, E>(
    threads: &[Handle],
    a: A,
    b: B,
) -> Result<Result<(RA, RB), E>, ContextError>
where
    A: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RA, E> + Send + 'static,
    B: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RB, E> + Send + 'static,
    RA: Send + 'static,
    RB: Send + 'static,
    E: Send + 'static,
{
    assert_eq!(threads.len(), 2, "expecting exactly two threads");

    let ctx_a = threads[0].take_ctx()?;
    let ctx_b = threads[1].take_ctx()?;

    let rx_a = spawn_task(threads[0].sender(), ctx_a, a)?;
    let rx_b = spawn_task(threads[1].sender(), ctx_b, b)?;

    // Await both concurrently. We must recover contexts from both tasks
    // even if one returns an error, so we cannot short-circuit here.
    let (result_a, result_b) = futures::join!(rx_a.recv(), rx_b.recv());

    let (output_a, ctx_a) = result_a.map_err(|_| recv_error())?;
    let (output_b, ctx_b) = result_b.map_err(|_| recv_error())?;

    threads[0].put_ctx(ctx_a);
    threads[1].put_ctx(ctx_b);

    Ok(match (output_a, output_b) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (Err(e), _) | (_, Err(e)) => Err(e),
    })
}

pub(crate) async fn try_join3<A, B, C, RA, RB, RC, E>(
    threads: &[Handle],
    a: A,
    b: B,
    c: C,
) -> Result<Result<(RA, RB, RC), E>, ContextError>
where
    A: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RA, E> + Send + 'static,
    B: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RB, E> + Send + 'static,
    C: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RC, E> + Send + 'static,
    RA: Send + 'static,
    RB: Send + 'static,
    RC: Send + 'static,
    E: Send + 'static,
{
    assert_eq!(threads.len(), 3, "expecting exactly three threads");

    let ctx_a = threads[0].take_ctx()?;
    let ctx_b = threads[1].take_ctx()?;
    let ctx_c = threads[2].take_ctx()?;

    let rx_a = spawn_task(threads[0].sender(), ctx_a, a)?;
    let rx_b = spawn_task(threads[1].sender(), ctx_b, b)?;
    let rx_c = spawn_task(threads[2].sender(), ctx_c, c)?;

    // Await all concurrently to recover contexts from every task.
    let (result_a, result_b, result_c) = futures::join!(rx_a.recv(), rx_b.recv(), rx_c.recv());

    let (output_a, ctx_a) = result_a.map_err(|_| recv_error())?;
    let (output_b, ctx_b) = result_b.map_err(|_| recv_error())?;
    let (output_c, ctx_c) = result_c.map_err(|_| recv_error())?;

    threads[0].put_ctx(ctx_a);
    threads[1].put_ctx(ctx_b);
    threads[2].put_ctx(ctx_c);

    Ok(match (output_a, output_b, output_c) {
        (Ok(a), Ok(b), Ok(c)) => Ok((a, b, c)),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
    })
}

pub(crate) async fn try_join4<A, B, C, D, RA, RB, RC, RD, E>(
    threads: &[Handle],
    a: A,
    b: B,
    c: C,
    d: D,
) -> Result<Result<(RA, RB, RC, RD), E>, ContextError>
where
    A: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RA, E> + Send + 'static,
    B: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RB, E> + Send + 'static,
    C: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RC, E> + Send + 'static,
    D: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RD, E> + Send + 'static,
    RA: Send + 'static,
    RB: Send + 'static,
    RC: Send + 'static,
    RD: Send + 'static,
    E: Send + 'static,
{
    assert_eq!(threads.len(), 4, "expecting exactly four threads");

    let ctx_a = threads[0].take_ctx()?;
    let ctx_b = threads[1].take_ctx()?;
    let ctx_c = threads[2].take_ctx()?;
    let ctx_d = threads[3].take_ctx()?;

    let rx_a = spawn_task(threads[0].sender(), ctx_a, a)?;
    let rx_b = spawn_task(threads[1].sender(), ctx_b, b)?;
    let rx_c = spawn_task(threads[2].sender(), ctx_c, c)?;
    let rx_d = spawn_task(threads[3].sender(), ctx_d, d)?;

    // Await all concurrently to recover contexts from every task.
    let (result_a, result_b, result_c, result_d) =
        futures::join!(rx_a.recv(), rx_b.recv(), rx_c.recv(), rx_d.recv());

    let (output_a, ctx_a) = result_a.map_err(|_| recv_error())?;
    let (output_b, ctx_b) = result_b.map_err(|_| recv_error())?;
    let (output_c, ctx_c) = result_c.map_err(|_| recv_error())?;
    let (output_d, ctx_d) = result_d.map_err(|_| recv_error())?;

    threads[0].put_ctx(ctx_a);
    threads[1].put_ctx(ctx_b);
    threads[2].put_ctx(ctx_c);
    threads[3].put_ctx(ctx_d);

    Ok(match (output_a, output_b, output_c, output_d) {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => Ok((a, b, c, d)),
        (Err(e), _, _, _) | (_, Err(e), _, _) | (_, _, Err(e), _) | (_, _, _, Err(e)) => Err(e),
    })
}
