//! Execution context.

#[cfg(any(test, feature = "test-utils"))]
mod test;

use std::sync::Arc;

use futures::{
    AsyncRead, AsyncWrite,
    future::{self, BoxFuture, Either},
};

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
/// Each context owns an I/O channel and a [`ContextId`]. Use [`join`],
/// [`try_join`], [`map`] etc. to run sub-tasks concurrently; whether they
/// actually execute in parallel depends on how the context was built.
///
/// [`join`]: Self::join
/// [`try_join`]: Self::try_join
/// [`map`]: Self::map
pub struct Context {
    id: ContextId,
    io: Io,
    mode: Mode,
    /// Sub-namespace counter incremented on each fork.
    fork_counter: u32,
}

enum Mode {
    Single,
    Multi {
        mux: Arc<dyn Mux + Send + Sync>,
        executor: Option<Arc<Inner>>,
    },
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match &self.mode {
            Mode::Single => "single",
            Mode::Multi {
                executor: Some(_), ..
            } => "multi-threaded",
            Mode::Multi { executor: None, .. } => "multi-cooperative",
        };
        f.debug_struct("Context")
            .field("id", &self.id)
            .field("io", &self.io)
            .field("mode", &mode)
            .finish()
    }
}

impl Context {
    /// Creates a new context that uses `mux` to allocate a channel per
    /// sub-task.
    ///
    /// Sub-tasks are executed cooperatively on the calling future. For
    /// parallel execution, build an [`Executor`](crate::Executor) and use
    /// [`Executor::new_context`](crate::Executor::new_context) instead.
    pub fn new<M: Mux + Send + Sync + 'static>(mux: M) -> Result<Self, ContextError> {
        Self::with_prefix(mux, ContextId::default())
    }

    /// Creates a new context backed by a single I/O channel.
    ///
    /// Sub-tasks spawned via [`join`], [`try_join`], [`map`] etc. share the
    /// channel and run **sequentially** in the order given.
    ///
    /// [`join`]: Self::join
    /// [`try_join`]: Self::try_join
    /// [`map`]: Self::map
    pub fn new_single_threaded<I>(io: I) -> Self
    where
        I: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        Self::from_io(Io::from_io(io))
    }

    pub(crate) fn from_io(io: Io) -> Self {
        Self {
            id: ContextId::default(),
            io,
            mode: Mode::Single,
            fork_counter: 0,
        }
    }

    /// Like [`Context::new`], but namespaces all channels under `prefix` so
    /// several sub-protocols can share a mux without colliding.
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
            mode: Mode::Multi {
                mux,
                executor: None,
            },
            fork_counter: 0,
        })
    }

    pub(crate) fn with_executor(
        id: ContextId,
        io: Io,
        mux: Arc<dyn Mux + Send + Sync>,
        executor: Arc<Inner>,
    ) -> Self {
        Self {
            id,
            io,
            mode: Mode::Multi {
                mux,
                executor: Some(executor),
            },
            fork_counter: 0,
        }
    }

    fn child(&self, id: ContextId) -> Result<Self, ContextError> {
        let Mode::Multi { mux, executor } = &self.mode else {
            unreachable!("child() called on a single-channel context");
        };
        let io = mux.open(id.as_ref()).map_err(ContextError::mux)?;
        Ok(Self {
            id,
            io,
            mode: Mode::Multi {
                mux: mux.clone(),
                executor: executor.clone(),
            },
            fork_counter: 0,
        })
    }

    fn next_fork(&mut self) -> ContextId {
        let base = self.id.child(self.fork_counter);
        self.fork_counter += 1;
        base
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

    /// Applies `f` to each item concurrently, returning the results in input
    /// order.
    pub async fn map<F, T, R>(&mut self, items: Vec<T>, f: F) -> Result<Vec<R>, ContextError>
    where
        F: for<'a> Fn(&'a mut Context, T) -> BoxFuture<'a, R> + Clone + Send + 'static,
        T: Send + 'static,
        R: Send + 'static,
    {
        if matches!(self.mode, Mode::Single) {
            let mut results = Vec::with_capacity(items.len());
            for item in items {
                results.push(f(self, item).await);
            }
            return Ok(results);
        }

        let parent_id = self.next_fork();
        let executor = self.executor().cloned();
        let mut tasks = Vec::with_capacity(items.len());
        for (i, item) in items.into_iter().enumerate() {
            let i = u32::try_from(i).expect("more than u32::MAX items");
            let mut ctx = self.child(parent_id.child(i))?;
            let f = f.clone();
            tasks.push(run(
                executor.as_ref(),
                async move { f(&mut ctx, item).await },
            ));
        }
        Ok(future::join_all(tasks).await)
    }

    /// Runs `a` and `b` concurrently and returns both results.
    pub async fn join<A, B, RA, RB>(&mut self, a: A, b: B) -> Result<(RA, RB), ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, RA> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, RB> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
    {
        if matches!(self.mode, Mode::Single) {
            let ra = a(self).await;
            let rb = b(self).await;
            return Ok((ra, rb));
        }

        let parent_id = self.next_fork();
        let executor = self.executor().cloned();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;

        let task_a = run(executor.as_ref(), async move { a(&mut ctx_a).await });
        let task_b = run(executor.as_ref(), async move { b(&mut ctx_b).await });
        Ok(future::join(task_a, task_b).await)
    }

    /// Like [`Context::join`], but short-circuits as soon as either branch
    /// returns an error, potentially cancelling the other.
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
        if matches!(self.mode, Mode::Single) {
            return Ok(async {
                let ra = a(self).await?;
                let rb = b(self).await?;
                Ok((ra, rb))
            }
            .await);
        }

        let parent_id = self.next_fork();
        let executor = self.executor().cloned();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;

        let task_a = run(executor.as_ref(), async move { a(&mut ctx_a).await });
        let task_b = run(executor.as_ref(), async move { b(&mut ctx_b).await });
        Ok(future::try_join(task_a, task_b).await)
    }

    /// Same as [`Context::try_join`], but with three branches.
    pub async fn try_join3<A, B, C, RA, RB, RC, E>(
        &mut self,
        a: A,
        b: B,
        c: C,
    ) -> Result<Result<(RA, RB, RC), E>, ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RA, E>> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RB, E>> + Send + 'static,
        C: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RC, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        RC: Send + 'static,
        E: Send + 'static,
    {
        if matches!(self.mode, Mode::Single) {
            return Ok(async {
                let ra = a(self).await?;
                let rb = b(self).await?;
                let rc = c(self).await?;
                Ok((ra, rb, rc))
            }
            .await);
        }

        let parent_id = self.next_fork();
        let executor = self.executor().cloned();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;
        let mut ctx_c = self.child(parent_id.child(2))?;

        let task_a = run(executor.as_ref(), async move { a(&mut ctx_a).await });
        let task_b = run(executor.as_ref(), async move { b(&mut ctx_b).await });
        let task_c = run(executor.as_ref(), async move { c(&mut ctx_c).await });
        Ok(future::try_join3(task_a, task_b, task_c).await)
    }

    /// Same as [`Context::try_join`], but with four branches.
    pub async fn try_join4<A, B, C, D, RA, RB, RC, RD, E>(
        &mut self,
        a: A,
        b: B,
        c: C,
        d: D,
    ) -> Result<Result<(RA, RB, RC, RD), E>, ContextError>
    where
        A: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RA, E>> + Send + 'static,
        B: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RB, E>> + Send + 'static,
        C: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RC, E>> + Send + 'static,
        D: for<'a> FnOnce(&'a mut Context) -> BoxFuture<'a, Result<RD, E>> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
        RC: Send + 'static,
        RD: Send + 'static,
        E: Send + 'static,
    {
        if matches!(self.mode, Mode::Single) {
            return Ok(async {
                let ra = a(self).await?;
                let rb = b(self).await?;
                let rc = c(self).await?;
                let rd = d(self).await?;
                Ok((ra, rb, rc, rd))
            }
            .await);
        }

        let parent_id = self.next_fork();
        let executor = self.executor().cloned();
        let mut ctx_a = self.child(parent_id.child(0))?;
        let mut ctx_b = self.child(parent_id.child(1))?;
        let mut ctx_c = self.child(parent_id.child(2))?;
        let mut ctx_d = self.child(parent_id.child(3))?;

        let task_a = run(executor.as_ref(), async move { a(&mut ctx_a).await });
        let task_b = run(executor.as_ref(), async move { b(&mut ctx_b).await });
        let task_c = run(executor.as_ref(), async move { c(&mut ctx_c).await });
        let task_d = run(executor.as_ref(), async move { d(&mut ctx_d).await });
        Ok(future::try_join4(task_a, task_b, task_c, task_d).await)
    }

    fn executor(&self) -> Option<&Arc<Inner>> {
        if let Mode::Multi { executor, .. } = &self.mode {
            executor.as_ref()
        } else {
            None
        }
    }
}

/// Spawns `fut` on `executor` if one is provided, otherwise yields the future
/// as-is. The output type is identical either way.
fn run<F>(
    executor: Option<&Arc<Inner>>,
    fut: F,
) -> impl std::future::Future<Output = F::Output> + Send
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    match executor {
        Some(exec) => Either::Left(crate::executor::spawn_on(exec, fut)),
        None => Either::Right(fut),
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
