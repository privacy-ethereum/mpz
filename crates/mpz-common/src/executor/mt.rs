use async_trait::async_trait;
use futures::{stream::FuturesOrdered, StreamExt};
use scoped_futures::ScopedBoxFuture;
use serio::IoDuplex;
use uid_mux::FramedUidMux;

use crate::{
    context::{ContextError, ErrorKind},
    Context, ThreadId,
};

const MAX_THREADS: usize = 255;

/// A multi-threaded executor.
#[derive(Debug)]
pub struct MTExecutor<M> {
    id: ThreadId,
    mux: M,
    concurrency: usize,
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
    /// * `concurrency` - The degree of concurrency to use.
    pub fn new(mux: M, concurrency: usize) -> Self {
        Self {
            id: ThreadId::default(),
            mux,
            concurrency,
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

        Ok(MTContext::new(id, self.mux.clone(), io, self.concurrency))
    }
}

/// A thread context from a multi-threaded executor.
#[derive(Debug)]
pub struct MTContext<M, Io> {
    id: ThreadId,
    mux: M,
    io: Io,
    // Child threads are created lazily, and are cached for reuse.
    children: Option<Children<M, Io>>,
}

impl<M, Io> MTContext<M, Io> {
    fn new(id: ThreadId, mux: M, io: Io, concurrency: usize) -> Self {
        let child_id = id.fork();

        Self {
            id,
            mux,
            io,
            children: Some(Children::new(child_id, concurrency)),
        }
    }
}

#[async_trait]
impl<M, Io> Context for MTContext<M, Io>
where
    M: FramedUidMux<ThreadId, Framed = Io> + Clone + Send + Sync,
    M::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    Io: IoDuplex + Send + Sync + Unpin + 'static,
{
    type Io = Io;

    fn id(&self) -> &ThreadId {
        &self.id
    }

    fn max_concurrency(&self) -> usize {
        self.children
            .as_ref()
            .expect("children were not left uninitialized")
            .max_concurrency()
    }

    fn io_mut(&mut self) -> &mut Self::Io {
        &mut self.io
    }

    async fn join<'a, A, B, RA, RB>(&'a mut self, a: A, b: B) -> Result<(RA, RB), ContextError>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'a,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'a,
        RA: Send + 'a,
        RB: Send + 'a,
    {
        // We temporarily take the children to avoid borrowing issues.
        let mut children = self
            .children
            .take()
            .expect("children were not left uninitialized");

        if children.len() < 2 {
            if let Err(e) = children.alloc(&self.mux, 2).await {
                self.children = Some(children);
                return Err(e);
            }
        }

        let [child_a, child_b] = children.first_n_mut();

        let output = futures::join!(a(child_a), b(child_b));

        self.children = Some(children);

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
        // We temporarily take the children to avoid borrowing issues.
        let mut children = self
            .children
            .take()
            .expect("children were not left uninitialized");

        if children.len() < 2 {
            if let Err(e) = children.alloc(&self.mux, 2).await {
                self.children = Some(children);
                return Err(e);
            }
        }

        let [child_a, child_b] = children.first_n_mut();

        let output = futures::try_join!(a(child_a), b(child_b));

        self.children = Some(children);

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
    use crate::{executor::test_mt_executor, join};

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

            join! {
                ctx,
                async {
                    *a = ctx.id().clone();
                },
                async {
                    *b = ctx.id().clone();
                }
            }
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
}
