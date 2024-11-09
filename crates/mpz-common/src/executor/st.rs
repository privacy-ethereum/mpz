//! Single-threaded executor.

use async_trait::async_trait;

use scoped_futures::ScopedBoxFuture;
use serio::{IoSink, IoStream};

use crate::{
    context::{Context, ContextError},
    ThreadId,
};

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
    #[inline]
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
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'static,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
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
    use serio::channel::duplex;

    use super::*;

    #[test]
    fn test_st_executor_join() {
        let (io, _) = duplex(1);
        let mut ctx = STExecutor::new(io);

        ctx.join(
            |ctx| async { println!("{}", ctx.id()) }.scope_boxed(),
            |ctx| async { println!("{}", ctx.id()) }.scope_boxed(),
        )
        .block_on()
        .unwrap();
    }
}
