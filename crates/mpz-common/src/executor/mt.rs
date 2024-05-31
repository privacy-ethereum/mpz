use async_trait::async_trait;
use futures::{stream::FuturesOrdered, StreamExt};
use scoped_futures::ScopedBoxFuture;
use serio::IoDuplex;
use uid_mux::FramedUidMux;

use crate::{
    context::{ContextError, ErrorKind},
    cpu::CpuBackend,
    Context, ThreadId,
};

const MAX_THREADS: usize = 255;

/// A multi-threaded executor.
#[derive(Debug)]
pub struct MTExecutor<M> {
    id: ThreadId,
    mux: M,
    max_concurrency: usize,
}

impl<M> MTExecutor<M>
where
    M: FramedUidMux<ThreadId> + Clone,
    M::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    /// Creates a new multi-threaded executor.
    ///
    /// # Arguments
    ///
    /// * `mux` - The multiplexer used by the executor.
    /// * `concurrency` - The max degree of concurrency to use.
    pub fn new(mux: M, max_concurrency: usize) -> Self {
        Self {
            id: ThreadId::default(),
            mux,
            max_concurrency,
        }
    }

    /// Creates a new thread.
    pub async fn new_thread(
        &mut self,
    ) -> Result<MTContext<M, <M as FramedUidMux<ThreadId>>::Framed>, ContextError> {
        let id = self.id.increment_in_place().ok_or_else(|| {
            ContextError::new(
                ErrorKind::Thread,
                "exceeded maximum number of threads (255)",
            )
        })?;

        let io = self
            .mux
            .open_framed(&id)
            .await
            .map_err(|e| ContextError::new(ErrorKind::Mux, e))?;

        Ok(MTContext::new(
            id,
            self.mux.clone(),
            io,
            self.max_concurrency,
        ))
    }
}

/// A thread context from a multi-threaded executor.
#[derive(Debug)]
pub struct MTContext<M, Io> {
    id: ThreadId,
    mux: M,
    // Ideally "scoped futures" would exist, but they don't, so we use an
    // `Option` to allow us to take the state out of the struct and send it
    // to another thread in `Context::blocking`.
    inner: Option<Inner<M, Io>>,
    max_concurrency: usize,
}

#[derive(Debug)]
struct Inner<M, Io> {
    io: Io,
    // Child threads are created lazily, and are cached for reuse.
    children: Children<M, Io>,
}

impl<M, Io> MTContext<M, Io> {
    fn new(id: ThreadId, mux: M, io: Io, max_concurrency: usize) -> Self {
        let child_id = id.fork();

        Self {
            id,
            mux,
            inner: Some(Inner {
                io,
                children: Children::new(child_id, max_concurrency),
            }),
            max_concurrency,
        }
    }

    #[inline]
    fn inner(&self) -> &Inner<M, Io> {
        self.inner
            .as_ref()
            .expect("context is never left uninitialized")
    }

    #[inline]
    fn inner_mut(&mut self) -> &mut Inner<M, Io> {
        self.inner
            .as_mut()
            .expect("context is never left uninitialized")
    }
}

#[async_trait]
impl<M, Io> Context for MTContext<M, Io>
where
    M: FramedUidMux<ThreadId, Framed = Io> + Clone + Send + Sync + 'static,
    M::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    Io: IoDuplex + Send + Sync + Unpin + 'static,
{
    type Io = Io;

    fn id(&self) -> &ThreadId {
        &self.id
    }

    fn max_concurrency(&self) -> usize {
        self.inner().children.max_concurrency()
    }

    fn io_mut(&mut self) -> &mut Self::Io {
        &mut self.inner_mut().io
    }

    async fn blocking<F, R>(&mut self, f: F) -> Result<R, ContextError>
    where
        F: for<'a> FnOnce(&'a mut Self) -> ScopedBoxFuture<'static, 'a, R> + Send + 'static,
        R: Send + 'static,
    {
        let mut ctx = Self {
            id: self.id.clone(),
            mux: self.mux.clone(),
            inner: self.inner.take(),
            max_concurrency: self.max_concurrency,
        };

        let (inner, output) = CpuBackend::blocking_async(async move {
            let output = f(&mut ctx).await;
            (ctx.inner, output)
        })
        .await;

        self.inner = inner;

        Ok(output)
    }

    async fn join<'a, A, B, RA, RB>(&'a mut self, a: A, b: B) -> Result<(RA, RB), ContextError>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'a,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'a,
        RA: Send + 'a,
        RB: Send + 'a,
    {
        // We temporarily take the state to avoid borrowing issues.
        let mut inner = self
            .inner
            .take()
            .expect("context is never left uninitialized");

        if inner.children.len() < 2 {
            if let Err(e) = inner.children.alloc(&self.mux, 2).await {
                self.inner = Some(inner);
                return Err(e);
            }
        }

        let [child_a, child_b] = inner.children.first_n_mut();

        let output = futures::join!(a(child_a), b(child_b));

        self.inner = Some(inner);

        Ok(output)
    }

    async fn try_join<'a, A, B, RA, RB, E>(
        &'a mut self,
        a: A,
        b: B,
    ) -> Result<Result<(RA, RB), E>, ContextError>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RA, E>> + Send + 'a,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RB, E>> + Send + 'a,
        RA: Send + 'a,
        RB: Send + 'a,
        E: Send + 'a,
    {
        // We temporarily take the state to avoid borrowing issues.
        let mut inner = self
            .inner
            .take()
            .expect("context is never left uninitialized");

        if inner.children.len() < 2 {
            if let Err(e) = inner.children.alloc(&self.mux, 2).await {
                self.inner = Some(inner);
                return Err(e);
            }
        }

        let [child_a, child_b] = inner.children.first_n_mut();

        let output = futures::try_join!(a(child_a), b(child_b));

        self.inner = Some(inner);

        Ok(output)
    }
}

#[derive(Debug)]
struct Children<M, Io> {
    id: ThreadId,
    slots: Vec<MTContext<M, Io>>,
    max_concurrency: usize,
}

impl<M, Io> Children<M, Io> {
    fn new(id: ThreadId, max_concurrency: usize) -> Self {
        Self {
            id,
            slots: Vec::new(),
            max_concurrency,
        }
    }

    fn max_concurrency(&self) -> usize {
        self.max_concurrency
    }
}

impl<M, Io> Children<M, Io>
where
    M: FramedUidMux<ThreadId, Framed = Io> + Clone,
    M::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    /// Returns the number of available child threads.
    fn len(&self) -> usize {
        self.slots.len()
    }

    /// Makes sure that there are at least `count` child threads available.
    async fn alloc(&mut self, mux: &M, count: usize) -> Result<(), ContextError> {
        if count > MAX_THREADS {
            return Err(ContextError::new(
                ErrorKind::Thread,
                "exceeded maximum number of threads (255)",
            ));
        }

        if self.slots.len() < count {
            let count = count - self.slots.len();
            let mut futs = FuturesOrdered::new();
            for _ in 0..count {
                let id = self
                    .id
                    .increment_in_place()
                    .expect("number of threads were checked");

                futs.push_back(async {
                    let io = mux
                        .open_framed(&id)
                        .await
                        .map_err(|e| ContextError::new(ErrorKind::Mux, e))?;

                    Ok(MTContext::new(id, mux.clone(), io, self.max_concurrency))
                });
            }

            while let Some(child) = futs.next().await.transpose()? {
                self.slots.push(child);
            }
        }

        Ok(())
    }

    fn first_n_mut<const N: usize>(&mut self) -> &mut [MTContext<M, Io>; N] {
        self.slots
            .first_chunk_mut()
            .expect("number of threads were checked")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serio::{stream::IoStreamExt, SinkExt};
    use tokio::sync::Barrier;

    use crate::{executor::test_mt_executor, scoped};

    use super::*;

    #[derive(Debug, Default)]
    struct LifetimeTest {
        a: ThreadId,
        b: ThreadId,
    }

    impl LifetimeTest {
        // This test is to ensure that the compiler is satisfied with the lifetimes
        // of the async closures passed to `join`.
        async fn foo<Ctx: Context>(&mut self, ctx: &mut Ctx) {
            let a = &mut self.a;
            let b = &mut self.b;

            ctx.join(
                scoped!(|ctx| *a = ctx.id().clone()),
                scoped!(|ctx| *b = ctx.id().clone()),
            )
            .await
            .unwrap();

            // Make sure we can mutate the fields after borrowing them in the async closures.
            self.a = ThreadId::default();
            self.b = ThreadId::default();
        }
    }

    #[tokio::test]
    async fn test_mt_executor_join() {
        let (mut exec_a, mut exec_b) = test_mt_executor(8);

        let (mut ctx_a, mut ctx_b) =
            futures::try_join!(exec_a.new_thread(), exec_b.new_thread()).unwrap();

        let mut test_a = LifetimeTest::default();
        let mut test_b = LifetimeTest::default();

        futures::join!(test_a.foo(&mut ctx_a), test_b.foo(&mut ctx_b));
    }

    #[tokio::test]
    async fn test_mt_executor_blocking() {
        let (mut exec_a, mut exec_b) = test_mt_executor(8);

        let (mut ctx_a, mut ctx_b) =
            futures::try_join!(exec_a.new_thread(), exec_b.new_thread()).unwrap();

        let (_, received) = futures::try_join!(
            ctx_a.blocking(scoped!(|ctx| ctx.io_mut().send(1u8).await.unwrap())),
            ctx_b.blocking(scoped!(|ctx| async move {
                ctx.io_mut().expect_next::<u8>().await.unwrap()
            }))
        )
        .unwrap();

        assert_eq!(received, 1u8);
        assert!(ctx_a.inner.is_some());
        assert!(ctx_b.inner.is_some());
    }

    #[tokio::test]
    // Tests that the mt executor polls futures concurrently.
    async fn test_mt_executor_concurrency() {
        let (mut exec_a, _) = test_mt_executor(8);
        let barrier = Arc::new(Barrier::new(2));

        let mut ctx = exec_a.new_thread().await.unwrap();

        let barrier_0 = barrier.clone();
        let barrier_1 = barrier.clone();

        ctx.join(
            scoped!(|_ctx| async move {
                barrier_0.wait().await;
            }),
            scoped!(|_ctx| async move {
                barrier_1.wait().await;
            }),
        )
        .await
        .unwrap();

        let barrier_0 = barrier.clone();
        let barrier_1 = barrier.clone();

        ctx.try_join(
            scoped!(|_ctx| async move { Ok::<_, ()>(barrier_0.wait().await) }),
            scoped!(|_ctx| async move { Ok::<_, ()>(barrier_1.wait().await) }),
        )
        .await
        .unwrap()
        .unwrap();
    }
}
