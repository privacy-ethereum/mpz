use async_trait::async_trait;

use scoped_futures::ScopedBoxFuture;
use serio::{IoSink, IoStream};

use crate::{context::Context, ThreadId};

/// A single-threaded executor.
pub struct STExecutor<Io> {
    id: ThreadId,
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
    pub fn new(io: Io) -> Self {
        Self {
            id: ThreadId::default(),
            io,
        }
    }
}

#[async_trait]
impl<Io> Context for STExecutor<Io>
where
    Io: IoSink + IoStream + Send + Unpin + 'static,
{
    type Io = Io;

    fn id(&self) -> &ThreadId {
        &self.id
    }

    fn io_mut(&mut self) -> &mut Self::Io {
        &mut self.io
    }

    async fn join<'a, A, B, RA, RB>(&'a mut self, a: A, b: B) -> (RA, RB)
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'a,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'a,
        RA: Send + 'a,
        RB: Send + 'a,
    {
        let a = a(self).await;
        let b = b(self).await;
        (a, b)
    }

    async fn try_join<'a, A, B, RA, RB, E>(&'a mut self, a: A, b: B) -> Result<(RA, RB), E>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RA, E>> + Send + 'a,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RB, E>> + Send + 'a,
        RA: Send + 'a,
        RB: Send + 'a,
        E: Send + 'a,
    {
        let a = a(self).await?;
        let b = b(self).await?;
        Ok((a, b))
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use scoped_futures::ScopedFutureExt;
    use serio::channel::duplex;

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
                |ctx| {
                    async move {
                        *a = ctx.id().clone();
                    }
                    .scope_boxed()
                },
                |ctx| {
                    async move {
                        *b = ctx.id().clone();
                    }
                    .scope_boxed()
                },
            )
            .await;

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
}
