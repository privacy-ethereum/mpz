use async_trait::async_trait;

use scoped_futures::ScopedBoxFuture;
use serio::{IoSink, IoStream};

use crate::{
    context::{Context, ContextError},
    cpu::CpuBackend,
    ThreadId,
};

/// A single-threaded executor.
pub struct STExecutor<Io> {
    id: ThreadId,
    // Ideally "scoped futures" would exist, but they don't, so we use an
    // `Option` to allow us to take the state out of the struct and send it
    // to another thread in `Context::blocking`.
    inner: Option<Inner<Io>>,
}

#[derive(Debug)]
struct Inner<Io> {
    io: Io,
}

impl<Io> STExecutor<Io>
where
    Io: IoSink + IoStream + Send + Unpin + 'static,
{
    /// Creates a new single-threaded executor.
    ///
    /// # Arguments
    ///
    /// * `io` - The I/O channel used by the executor.
    #[inline]
    pub fn new(io: Io) -> Self {
        Self {
            id: ThreadId::default(),
            inner: Some(Inner { io }),
        }
    }

    #[inline]
    fn inner(&mut self) -> &mut Inner<Io> {
        self.inner
            .as_mut()
            .expect("context is never left uninitialized")
    }
}

#[async_trait]
impl<Io> Context for STExecutor<Io>
where
    Io: IoSink + IoStream + Send + Sync + Unpin + 'static,
{
    type Io = Io;

    fn id(&self) -> &ThreadId {
        &self.id
    }

    fn max_concurrency(&self) -> usize {
        1
    }

    fn io_mut(&mut self) -> &mut Self::Io {
        &mut self.inner().io
    }

    async fn blocking<F, R>(&mut self, f: F) -> Result<R, ContextError>
    where
        F: for<'a> FnOnce(&'a mut Self) -> ScopedBoxFuture<'static, 'a, R> + Send + 'static,
        R: Send + 'static,
    {
        let mut ctx = Self {
            id: self.id.clone(),
            inner: self.inner.take(),
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
        let a = a(self).await;
        let b = b(self).await;
        Ok((a, b))
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
        let try_join = |a: A, b: B| async move {
            let a = a(self).await?;
            let b = b(self).await?;
            Ok((a, b))
        };

        Ok(try_join(a, b).await)
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use serio::channel::duplex;

    use crate::scoped;

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

    #[test]
    fn test_st_executor_join() {
        let (io, _) = duplex(1);
        let mut ctx = STExecutor::new(io);
        let mut test = LifetimeTest::default();

        block_on(test.foo(&mut ctx));
    }

    #[test]
    fn test_st_executor_blocking() {
        let (io, _) = duplex(1);
        let mut ctx = STExecutor::new(io);

        block_on(async {
            let id = ctx.blocking(scoped!(|ctx| ctx.id().clone())).await.unwrap();

            assert_eq!(&id, ctx.id());
            assert!(ctx.inner.is_some());
        });
    }
}
