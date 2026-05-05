//! Execution context.

#[cfg(any(test, feature = "test-utils"))]
mod test;

use std::sync::Arc;

use futures::future::{BoxFuture, Either};

#[cfg(any(test, feature = "test-utils"))]
pub use test::{
    RecordedMtData, RecordingDuplex, ReplayDuplex, recording_mt_context,
    recording_mt_context_with_limit, recording_mt_context_with_spawn_and_limit,
    recording_st_context, recording_st_context_with_limit, replay_mt_context,
    replay_mt_context_with_limit, replay_mt_context_with_spawn_and_limit, replay_st_context,
    test_mt_context, test_mt_context_with_spawn, test_st_context,
};

use crate::{ContextId, executor::Inner, io::Io, mux::Mux};

/// A task execution context.
///
/// Each context has a unique [`ContextId`] and its own I/O channel.
/// Child tasks created via [`try_join`](Self::try_join) etc. run either:
/// - Cooperatively via async interleaving (single-threaded mode)
/// - In parallel via work-stealing executor (multi-threaded mode)
pub struct Context {
    id: ContextId,
    io: Io,
    mux: Arc<dyn Mux + Send + Sync>,
    executor: Option<Arc<Inner>>,
    /// Sub-namespace counter incremented on each fork.
    fork_counter: u32,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("id", &self.id)
            .field("io", &self.io)
            .field("executor", &self.executor.is_some())
            .finish()
    }
}

impl Context {
    /// Creates a new context in single-threaded mode rooted at
    /// [`ContextId::default`].
    pub fn new<M: Mux + Send + Sync + 'static>(mux: M) -> Result<Self, ContextError> {
        Self::with_prefix(mux, ContextId::default())
    }

    /// Creates a new context in single-threaded mode rooted at the given byte
    /// prefix.
    ///
    /// All child contexts forked off this one will be namespaced under
    /// `prefix`, allowing several sub-protocols to share a mux without
    /// collisions.
    pub fn with_prefix<M: Mux + Send + Sync + 'static>(
        mux: M,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Self, ContextError> {
        let mux: Arc<dyn Mux + Send + Sync> = Arc::new(mux);
        let id = ContextId::from_prefix(prefix);
        let io = mux.open(id.as_ref()).map_err(ContextError::mux)?;
        Ok(Self {
            id,
            io,
            mux,
            executor: None,
            fork_counter: 0,
        })
    }

    /// Creates a new context in multi-threaded mode.
    pub(crate) fn with_executor(
        id: ContextId,
        io: Io,
        mux: Arc<dyn Mux + Send + Sync>,
        executor: Arc<Inner>,
    ) -> Self {
        Self {
            id,
            io,
            mux,
            executor: Some(executor),
            fork_counter: 0,
        }
    }

    /// Creates a child context with the given ID.
    fn child(&self, id: ContextId) -> Result<Self, ContextError> {
        let io = self.mux.open(id.as_ref()).map_err(ContextError::mux)?;
        Ok(Self {
            id,
            io,
            mux: self.mux.clone(),
            executor: self.executor.clone(),
            fork_counter: 0,
        })
    }

    /// Returns a fresh fork base ID, advancing this context's fork counter.
    fn next_fork(&mut self) -> ContextId {
        let base = self.id.child(self.fork_counter);
        self.fork_counter += 1;
        base
    }

    /// Spawns the future on the executor if one is available, otherwise returns
    /// it as-is. The result is a future of the same output type.
    fn run<F>(&self, fut: F) -> impl std::future::Future<Output = F::Output> + Send
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match &self.executor {
            Some(exec) => Either::Left(crate::executor::spawn_on(exec, fut)),
            None => Either::Right(fut),
        }
    }

    /// Returns the context ID.
    pub fn id(&self) -> &ContextId {
        &self.id
    }

    /// Returns a reference to the I/O channel.
    pub fn io(&self) -> &Io {
        &self.io
    }

    /// Returns a mutable reference to the I/O channel.
    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    /// Executes a collection of tasks concurrently.
    ///
    /// Each task is assigned a deterministic child ID based on its index.
    /// Results are returned in the original order.
    pub async fn map<F, T, R>(&mut self, items: Vec<T>, f: F) -> Result<Vec<R>, ContextError>
    where
        F: for<'a> Fn(&'a mut Context, T) -> BoxFuture<'a, R> + Clone + Send + 'static,
        T: Send + 'static,
        R: Send + 'static,
    {
        let parent_id = self.next_fork();
        let mut tasks = Vec::with_capacity(items.len());
        for (i, item) in items.into_iter().enumerate() {
            let mut ctx = self.child(parent_id.child(i as u32))?;
            let f = f.clone();
            tasks.push(self.run(async move { f(&mut ctx, item).await }));
        }
        Ok(futures::future::join_all(tasks).await)
    }

    /// Executes two tasks concurrently.
    pub async fn join<A, B, RA, RB>(&mut self, a: A, b: B) -> Result<(RA, RB), ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, RA> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, RB> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
    {
        let parent_id = self.next_fork();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;

        let task_a = self.run(async move { a(&mut ctx_a).await });
        let task_b = self.run(async move { b(&mut ctx_b).await });
        Ok(futures::future::join(task_a, task_b).await)
    }

    /// Executes two fallible tasks concurrently, returning early on error.
    pub async fn try_join<A, B, RA, RB, E>(
        &mut self,
        a: A,
        b: B,
    ) -> Result<Result<(RA, RB), E>, ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RA, E>> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RB, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        E: Send + 'static,
    {
        let parent_id = self.next_fork();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;

        let task_a = self.run(async move { a(&mut ctx_a).await });
        let task_b = self.run(async move { b(&mut ctx_b).await });
        Ok(futures::future::try_join(task_a, task_b).await)
    }

    /// Executes three fallible tasks concurrently, returning early on error.
    pub async fn try_join3<A, B, C, RA, RB, RC, E>(
        &mut self,
        a: A,
        b: B,
        c: C,
    ) -> Result<Result<(RA, RB, RC), E>, ContextError>
    where
        A: for<'x> FnOnce(&'x mut Context) -> BoxFuture<'x, Result<RA, E>> + Send + 'static,
        B: for<'x> FnOnce(&'x mut Context) -> BoxFuture<'x, Result<RB, E>> + Send + 'static,
        C: for<'x> FnOnce(&'x mut Context) -> BoxFuture<'x, Result<RC, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        RC: Send + 'static,
        E: Send + 'static,
    {
        let parent_id = self.next_fork();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;
        let mut ctx_c = self.child(parent_id.child(2))?;

        let task_a = self.run(async move { a(&mut ctx_a).await });
        let task_b = self.run(async move { b(&mut ctx_b).await });
        let task_c = self.run(async move { c(&mut ctx_c).await });
        Ok(futures::future::try_join3(task_a, task_b, task_c).await)
    }

    /// Executes four fallible tasks concurrently, returning early on error.
    pub async fn try_join4<A, B, C, D, RA, RB, RC, RD, E>(
        &mut self,
        a: A,
        b: B,
        c: C,
        d: D,
    ) -> Result<Result<(RA, RB, RC, RD), E>, ContextError>
    where
        A: for<'x> FnOnce(&'x mut Context) -> BoxFuture<'x, Result<RA, E>> + Send + 'static,
        B: for<'x> FnOnce(&'x mut Context) -> BoxFuture<'x, Result<RB, E>> + Send + 'static,
        C: for<'x> FnOnce(&'x mut Context) -> BoxFuture<'x, Result<RC, E>> + Send + 'static,
        D: for<'x> FnOnce(&'x mut Context) -> BoxFuture<'x, Result<RD, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        RC: Send + 'static,
        RD: Send + 'static,
        E: Send + 'static,
    {
        let parent_id = self.next_fork();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;
        let mut ctx_c = self.child(parent_id.child(2))?;
        let mut ctx_d = self.child(parent_id.child(3))?;

        let task_a = self.run(async move { a(&mut ctx_a).await });
        let task_b = self.run(async move { b(&mut ctx_b).await });
        let task_c = self.run(async move { c(&mut ctx_c).await });
        let task_d = self.run(async move { d(&mut ctx_d).await });
        Ok(futures::future::try_join4(task_a, task_b, task_c, task_d).await)
    }
}

/// Error for [`Context`].
#[derive(Debug, thiserror::Error)]
#[error("context mux error")]
pub struct ContextError {
    #[source]
    source: std::io::Error,
}

impl ContextError {
    fn mux(source: std::io::Error) -> Self {
        Self { source }
    }
}
