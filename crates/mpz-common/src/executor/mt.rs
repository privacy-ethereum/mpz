//! Multi-threaded executor.
//!
//! The multi-threaded executor runs each logical thread on its own system
//! thread with a dedicated I/O channel.

mod spawn;
mod worker;

use futures::{stream::FuturesUnordered, StreamExt};
pub use spawn::{Spawn, SpawnError, StdSpawn};

use std::{fmt::Debug, future::Future, pin::Pin, sync::Arc};

use async_trait::async_trait;
use pollster::FutureExt as _;
use scoped_futures::ScopedBoxFuture;
use serio::IoDuplex;
use uid_mux::FramedUidMux;

use crate::{
    context::{ContextError, ErrorKind},
    load_balance::distribute_by_weight,
    Context, ThreadId,
};
use worker::{Handle, Worker};

#[async_trait]
trait SpawnCtx<Ctx>: Send + Sync {
    async fn spawn_ctx(&self, id: ThreadId) -> Result<Handle<Ctx>, ContextError>;
}

/// Config for [`MTExecutor`].
#[derive(Debug, Clone)]
pub struct MTConfig {
    max_concurrency: usize,
}

impl Default for MTConfig {
    fn default() -> Self {
        Self { max_concurrency: 8 }
    }
}

/// A multi-threaded executor.
#[derive(Debug)]
pub struct MTExecutor<M, S = StdSpawn> {
    id: ThreadId,
    spawner: Spawner<M, S>,
}

impl<M> MTExecutor<M>
where
    M: FramedUidMux<ThreadId> + Send + Sync + 'static,
    M::Framed: Send + 'static,
    M::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    /// Creates a new multi-threaded executor.
    pub fn new(mux: M, config: MTConfig) -> Self {
        Self::new_with_spawner(mux, StdSpawn, config)
    }
}

impl<M, S> MTExecutor<M, S>
where
    M: FramedUidMux<ThreadId> + Send + Sync + 'static,
    M::Framed: IoDuplex + Send + 'static,
    M::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    S: Spawn + Send + Sync + 'static,
{
    /// Creates a new multi-threaded executor with a custom spawner.
    pub fn new_with_spawner(mux: M, spawn: S, config: MTConfig) -> Self {
        Self {
            id: ThreadId::default(),
            spawner: Spawner::new(mux, spawn, config),
        }
    }

    /// Returns a future that yields a new thread context.
    pub fn new_thread(&mut self) -> NewThread<<M as FramedUidMux<ThreadId>>::Framed> {
        let id = self.id.increment_in_place().ok_or_else(|| {
            ContextError::new(
                ErrorKind::Thread,
                "exceeded maximum number of threads (255)",
            )
        });

        let spawner = self.spawner.clone();

        NewThread {
            fut: Box::pin(async move {
                let id = id?;
                spawner.spawn(id).await
            }),
        }
    }
}

pin_project_lite::pin_project! {
    /// A future that yields a new thread context.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct NewThread<Io> {
        #[pin]
        fut: Pin<Box<dyn Future<Output = Result<MTContext<Io>, ContextError>> + Send>>,
    }
}

impl<Io> Future for NewThread<Io> {
    type Output = Result<MTContext<Io>, ContextError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

#[derive(Debug)]
struct Spawner<M, S> {
    inner: Arc<Inner<M, S>>,
}

impl<M, S> Spawner<M, S> {
    fn new(mux: M, spawn: S, config: MTConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                mux,
                spawn,
                config: Arc::new(config),
            }),
        }
    }
}

impl<M, S> Clone for Spawner<M, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<M, S> Spawner<M, S>
where
    M: FramedUidMux<ThreadId> + Send + Sync + 'static,
    M::Framed: Send + 'static,
    M::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    S: Spawn + Send + Sync + 'static,
{
    async fn spawn(&self, id: ThreadId) -> Result<MTContext<M::Framed>, ContextError> {
        let io = self
            .inner
            .mux
            .open_framed(&id)
            .await
            .map_err(|e| ContextError::new(ErrorKind::Mux, e))?;

        Ok(MTContext {
            id: id.clone(),
            config: self.inner.config.clone(),
            io,
            spawner: Box::new(self.clone()),
            child_id: id.fork(),
            children: Vec::new(),
        })
    }
}

#[derive(Debug)]
struct Inner<M, S> {
    mux: M,
    spawn: S,
    config: Arc<MTConfig>,
}

#[async_trait]
impl<M, S> SpawnCtx<MTContext<M::Framed>> for Spawner<M, S>
where
    M: FramedUidMux<ThreadId> + Send + Sync + 'static,
    M::Framed: Send + 'static,
    M::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    S: Spawn + Send + Sync + 'static,
{
    async fn spawn_ctx(&self, id: ThreadId) -> Result<Handle<MTContext<M::Framed>>, ContextError> {
        let ctx = self.spawn(id.clone()).await?;

        let (worker, handle) = Worker::new(id, ctx);

        self.inner
            .spawn
            .spawn(move || worker.run())
            .map_err(|e| ContextError::new(ErrorKind::Thread, e))?;

        Ok(handle)
    }
}

/// A thread context from a multi-threaded executor.
pub struct MTContext<Io> {
    id: ThreadId,
    config: Arc<MTConfig>,
    io: Io,
    spawner: Box<dyn SpawnCtx<Self>>,
    child_id: ThreadId,
    children: Vec<Handle<Self>>,
}

impl<Io> MTContext<Io> {
    /// Returns a child thread.
    async fn get_child(&mut self) -> Result<&Handle<Self>, ContextError> {
        if self.children.is_empty() {
            let id = self.child_id.increment_in_place().ok_or_else(|| {
                ContextError::new(ErrorKind::Thread, "thread ID overflow".to_string())
            })?;

            let child = self.spawner.spawn_ctx(id).await?;
            self.children.push(child);
        }

        Ok(self
            .children
            .first()
            .expect("child thread should be available"))
    }

    async fn get_children(&mut self, count: usize) -> Result<&[Handle<Self>], ContextError> {
        if count > self.config.max_concurrency {
            return Err(ContextError::new(
                ErrorKind::Thread,
                "requested concurrency exceeds maximum".to_string(),
            ));
        } else if self.children.len() < count {
            let diff = count - self.children.len();
            for _ in 0..diff {
                let id = self.child_id.increment_in_place().ok_or_else(|| {
                    ContextError::new(ErrorKind::Thread, "thread ID overflow".to_string())
                })?;

                let child = self.spawner.spawn_ctx(id).await?;
                self.children.push(child);
            }
        }

        Ok(&self.children)
    }
}

impl<Io> Debug for MTContext<Io> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MTContext")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<Io> Context for MTContext<Io>
where
    Io: IoDuplex + Send + Sync + Unpin + 'static,
{
    type Io = Io;

    fn id(&self) -> &ThreadId {
        &self.id
    }

    fn max_concurrency(&self) -> usize {
        self.config.max_concurrency
    }

    fn io_mut(&mut self) -> &mut Self::Io {
        &mut self.io
    }

    async fn map<'a, F, T, R, W>(
        &'a mut self,
        items: Vec<T>,
        f: F,
        weight: W,
    ) -> Result<Vec<R>, ContextError>
    where
        F: for<'b> Fn(&'b mut Self, T) -> ScopedBoxFuture<'static, 'b, R> + Clone + Send + 'static,
        T: Send + 'static,
        R: Send + 'static,
        W: Fn(&T) -> usize + Send + 'static,
    {
        let item_count = items.len();
        let concurrency = self.config.max_concurrency.min(item_count);

        // If concurrency is 1, execute with this context.
        if concurrency == 1 {
            let mut outputs = Vec::with_capacity(item_count);
            for item in items {
                outputs.push(f(self, item).await);
            }
            return Ok(outputs);
        }

        let children = self.get_children(concurrency - 1).await?;

        let items = items.into_iter().enumerate().collect::<Vec<_>>();
        let mut lanes = distribute_by_weight(items, |item| weight(&item.1), concurrency);
        let self_lane = lanes.pop().expect("should be at least 1 lane");

        let mut queue = FuturesUnordered::new();
        for (lane, child) in lanes.into_iter().zip(children) {
            let f = f.clone();
            let task = child.send_with_return(move |ctx| {
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
        for (i, item) in self_lane {
            outputs.push((i, f(self, item).await));
        }

        while let Some(lane) = queue.next().await {
            outputs.extend(lane?);
        }

        outputs.sort_by_key(|(i, _)| *i);

        Ok(outputs.into_iter().map(|(_, output)| output).collect())
    }

    async fn join<'a, A, B, RA, RB>(&'a mut self, a: A, b: B) -> Result<(RA, RB), ContextError>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'static,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
    {
        // Send job to child thread, it will start executing immediately.
        let rb = self
            .get_child()
            .await?
            .send_with_return(|ctx| b(ctx).block_on())?;

        let ra = a(self).await;
        let rb = rb.await?;

        Ok((ra, rb))
    }

    async fn try_join<'a, A, B, RA, RB, E>(
        &'a mut self,
        a: A,
        b: B,
    ) -> Result<Result<(RA, RB), E>, ContextError>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RA, E>> + Send + 'static,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RB, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        E: Send + 'static,
    {
        // Send job to child thread, it will start executing immediately.
        let rb = self
            .get_child()
            .await?
            .send_with_return(|ctx| b(ctx).block_on())?;

        let ra = match a(self).await {
            Ok(ra) => ra,
            Err(e) => return Ok(Err(e)),
        };

        Ok(rb.await?.map(|rb| (ra, rb)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use scoped_futures::ScopedFutureExt;
    use tokio::sync::Barrier;

    use crate::executor::test_mt_executor;

    use super::*;

    #[tokio::test]
    async fn test_mt_executor_join() {
        let (mut exec_a, _) = test_mt_executor(8, MTConfig::default());

        let mut ctx = exec_a.new_thread().await.unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let barrier_0 = barrier.clone();
        let barrier_1 = barrier.clone();

        let (id_0, id_1) = ctx
            .join(
                |ctx| {
                    async move {
                        barrier_0.wait().await;
                        ctx.id().clone()
                    }
                    .scope_boxed()
                },
                |ctx| {
                    async move {
                        barrier_1.wait().await;
                        ctx.id().clone()
                    }
                    .scope_boxed()
                },
            )
            .await
            .unwrap();

        assert_eq!(id_0.as_bytes(), &[0]);
        assert_eq!(id_1.as_bytes(), &[0, 0]);
    }

    #[tokio::test]
    async fn test_mt_executor_try_join() {
        let (mut exec_a, _) = test_mt_executor(8, MTConfig::default());

        let mut ctx = exec_a.new_thread().await.unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let barrier_0 = barrier.clone();
        let barrier_1 = barrier.clone();

        let (id_0, id_1) = ctx
            .try_join(
                |ctx| {
                    async move {
                        barrier_0.wait().await;
                        Ok::<_, ()>(ctx.id().clone())
                    }
                    .scope_boxed()
                },
                |ctx| {
                    async move {
                        barrier_1.wait().await;
                        Ok::<_, ()>(ctx.id().clone())
                    }
                    .scope_boxed()
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(id_0.as_bytes(), &[0]);
        assert_eq!(id_1.as_bytes(), &[0, 0]);
    }
}
