use async_trait::async_trait;

use scoped_futures::ScopedBoxFuture;
use serio::{Sink, Stream};

use crate::{context::Context, cpu::CpuBackend, ContextError, ThreadId};

/// A dummy executor.
#[derive(Debug, Default)]
pub struct DummyExecutor {
    id: ThreadId,
    io: DummyIo,
}

/// A dummy I/O.
#[derive(Debug, Default)]
pub struct DummyIo;

impl Sink for DummyIo {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send<Item: serio::Serialize>(
        self: std::pin::Pin<&mut Self>,
        _item: Item,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Stream for DummyIo {
    type Error = std::io::Error;

    fn poll_next<Item: serio::Deserialize>(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Item, Self::Error>>> {
        std::task::Poll::Ready(None)
    }
}

#[async_trait]
impl Context for DummyExecutor {
    type Io = DummyIo;

    fn id(&self) -> &ThreadId {
        &self.id
    }

    fn max_concurrency(&self) -> usize {
        1
    }

    fn io_mut(&mut self) -> &mut Self::Io {
        &mut self.io
    }

    async fn blocking<F, R>(&mut self, f: F) -> Result<R, ContextError>
    where
        F: for<'a> FnOnce(&'a mut Self) -> ScopedBoxFuture<'static, 'a, R> + Send + 'static,
        R: Send + 'static,
    {
        let mut ctx = Self {
            id: self.id.clone(),
            io: DummyIo,
        };

        Ok(CpuBackend::blocking_async(async move { f(&mut ctx).await }).await)
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
    fn test_dummy_executor_join() {
        let mut ctx = DummyExecutor::default();
        let mut test = LifetimeTest::default();

        block_on(test.foo(&mut ctx));
    }
}
