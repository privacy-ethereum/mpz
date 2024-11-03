//! Dummy executor.

use async_trait::async_trait;

use scoped_futures::ScopedBoxFuture;
use serio::{Sink, Stream};

use crate::{context::Context, ContextError, ThreadId};

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

    async fn map<'a, F, T, R, W>(
        &'a mut self,
        items: Vec<T>,
        f: F,
        _weight: W,
    ) -> Result<Vec<R>, ContextError>
    where
        F: for<'b> Fn(&'b mut Self, T) -> ScopedBoxFuture<'static, 'b, R> + Clone + Send + 'static,
        T: Send + 'static,
        R: Send + 'static,
        W: Fn(&T) -> usize + Send + 'static,
    {
        let mut results = Vec::with_capacity(items.len());
        for item in items {
            results.push(f(self, item).await);
        }
        Ok(results)
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
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RA, E>> + Send + 'static,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RB, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        E: Send + 'static,
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
    use pollster::FutureExt;
    use scoped_futures::ScopedFutureExt;

    use super::*;

    #[test]
    fn test_dummy_executor_join() {
        let mut ctx = DummyExecutor::default();

        ctx.join(
            |ctx| async { println!("{}", ctx.id()) }.scope_boxed(),
            |ctx| async { println!("{}", ctx.id()) }.scope_boxed(),
        )
        .block_on()
        .unwrap();
    }
}
