mod builder;
mod spawn;
mod worker;

use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use futures::{stream::FuturesUnordered, FutureExt, StreamExt as _};
use pollster::FutureExt as _;
use scoped_futures::ScopedBoxFuture;
use worker::{Handle, Worker};

use crate::{
    context::ErrorKind, load_balance::distribute_by_weight, mux::Mux, Context, ContextError,
    ThreadId,
};

pub use builder::{MultithreadBuilder, MultithreadBuilderError};
pub use spawn::{CustomSpawn, Spawn, SpawnError, StdSpawn};

#[derive(Debug)]
pub(crate) struct MtConfig {
    concurrency: usize,
}

/// A multi-threaded context.
#[derive(Debug)]
pub struct Multithread {
    current_id: ThreadId,
    config: Arc<MtConfig>,
    builder: Arc<Mutex<ThreadBuilder>>,
}

impl Multithread {
    /// Creates a new builder.
    pub fn builder() -> MultithreadBuilder {
        MultithreadBuilder::default()
    }

    /// Creates a new multi-threaded context.
    pub async fn new_context(&mut self) -> Result<Context, ContextError> {
        let id = self.current_id.increment().ok_or_else(|| {
            ContextError::new(ErrorKind::Thread, "thread ID overflow".to_string())
        })?;

        let io = { self.builder.lock().unwrap().mux.open(id.clone()) }
            .await
            .map_err(|e| ContextError::new(ErrorKind::Mux, e))?;

        let ctx =
            Context::new_multi_threaded(id.clone(), io, self.config.clone(), self.builder.clone());

        Ok(ctx)
    }
}

pub(crate) struct ThreadBuilder {
    spawn: Box<dyn Spawn + Send>,
    mux: Box<dyn Mux + Send>,
}

impl ThreadBuilder {
    fn spawn(
        this: Arc<Mutex<Self>>,
        id: ThreadId,
        config: Arc<MtConfig>,
    ) -> impl Future<Output = Result<Handle, ContextError>> + Send {
        async move {
            let io_fut = { this.lock().unwrap().mux.open(id.clone()) };

            let io = io_fut
                .await
                .map_err(|e| ContextError::new(ErrorKind::Mux, e))?;

            let ctx = Context::new_multi_threaded(id.clone(), io, config, this.clone());
            let (worker, handle) = Worker::new(id, ctx);

            this.lock()
                .unwrap()
                .spawn
                .spawn(Box::new(move || worker.run()))?;

            Ok(handle)
        }
    }
}

impl std::fmt::Debug for ThreadBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadBuilder").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct Threads {
    config: Arc<MtConfig>,
    builder: Arc<Mutex<ThreadBuilder>>,
    child_id: ThreadId,
    children: Vec<Handle>,
}

impl Threads {
    pub(crate) fn new(
        parent_id: ThreadId,
        config: Arc<MtConfig>,
        builder: Arc<Mutex<ThreadBuilder>>,
    ) -> Self {
        Self {
            config,
            builder,
            child_id: parent_id.fork(),
            children: Vec::new(),
        }
    }

    pub(crate) fn concurrency(&self) -> usize {
        self.config.concurrency
    }

    pub(crate) async fn get(&mut self, count: usize) -> Result<&[Handle], ContextError> {
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

                let child =
                    ThreadBuilder::spawn(self.builder.clone(), id, self.config.clone()).await?;
                self.children.push(child);
            }
        }

        Ok(&self.children[..count])
    }
}

pub(crate) async fn map<F, T, R, W>(
    threads: &[Handle],
    items: Vec<T>,
    f: F,
    weight: W,
) -> Result<Vec<R>, ContextError>
where
    F: for<'b> Fn(&'b mut Context, T) -> ScopedBoxFuture<'static, 'b, R> + Clone + Send + 'static,
    T: Send + 'static,
    R: Send + 'static,
    W: Fn(&T) -> usize + Send + 'static,
{
    let items = items.into_iter().enumerate().collect::<Vec<_>>();
    let item_count = items.len();
    let lanes = distribute_by_weight(items, |item| weight(&item.1), threads.len());

    let mut queue = FuturesUnordered::new();
    for (lane, thread) in lanes.into_iter().zip(threads) {
        let f = f.clone();
        let task = thread.send_with_return(move |ctx| {
            async move {
                let mut outputs = Vec::with_capacity(lane.len());
                for (i, item) in lane {
                    outputs.push((i, f(ctx, item).await));
                }
                outputs
            }
            .block_on()
        })?;
        queue.push(task);
    }

    let mut outputs = Vec::with_capacity(item_count);
    while let Some(lane) = queue.next().await {
        outputs.extend(lane?);
    }

    outputs.sort_by_key(|(i, _)| *i);

    Ok(outputs.into_iter().map(|(_, output)| output).collect())
}

pub(crate) async fn join<'a, A, B, RA, RB>(
    threads: &[Handle],
    a: A,
    b: B,
) -> Result<(RA, RB), ContextError>
where
    A: for<'b> FnOnce(&'b mut Context) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'static,
    B: for<'b> FnOnce(&'b mut Context) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'static,
    RA: Send + 'static,
    RB: Send + 'static,
{
    assert_eq!(threads.len(), 2, "expecting exactly two threads");

    let ra = threads[0].send_with_return(|ctx| a(ctx).block_on())?;
    let rb = threads[1].send_with_return(|ctx| b(ctx).block_on())?;

    let (ra, rb) = futures::try_join!(ra, rb)?;

    Ok((ra, rb))
}

pub(crate) async fn try_join<'a, A, B, RA, RB, E>(
    threads: &[Handle],
    a: A,
    b: B,
) -> Result<Result<(RA, RB), E>, ContextError>
where
    A: for<'b> FnOnce(&'b mut Context) -> ScopedBoxFuture<'a, 'b, Result<RA, E>> + Send + 'static,
    B: for<'b> FnOnce(&'b mut Context) -> ScopedBoxFuture<'a, 'b, Result<RB, E>> + Send + 'static,
    RA: Send + 'static,
    RB: Send + 'static,
    E: Send + 'static,
{
    assert_eq!(threads.len(), 2, "expecting exactly two threads");

    let mut a = threads[0].send_with_return(|ctx| a(ctx).block_on())?.fuse();
    let mut b = threads[1].send_with_return(|ctx| b(ctx).block_on())?.fuse();

    let mut ra = None;
    let mut rb = None;
    loop {
        futures::select! {
            output = a => {
                match output? {
                    Ok(output) => ra = Some(output),
                    Err(error) => return Ok(Err(error)),
                }
            },
            output = b => {
                match output? {
                    Ok(output) => rb = Some(output),
                    Err(error) => return Ok(Err(error)),
                }
            }
            complete => break,
        }
    }

    let ra = ra.expect("a future should have resolved");
    let rb = rb.expect("b future should have resolved");

    Ok(Ok((ra, rb)))
}
