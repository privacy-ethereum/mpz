//! Execution context.

mod mt;
mod st;
#[cfg(any(test, feature = "test-utils"))]
mod test;

pub use mt::{
    CustomSpawn, Multithread, MultithreadBuilder, MultithreadBuilderError, Spawn, SpawnError,
    StdSpawn,
};
#[cfg(any(test, feature = "test-utils"))]
pub use test::{test_mt_context, test_st_context};

use core::fmt;
use std::sync::{Arc, Mutex};

use futures::{AsyncRead, AsyncWrite};
use scoped_futures::ScopedBoxFuture;

use crate::{
    context::mt::{MtConfig, ThreadBuilder, Threads},
    io::Io,
    ThreadId,
};

/// A thread context.
#[derive(Debug)]
pub struct Context {
    id: ThreadId,
    io: Io,
    mode: Mode,
}

impl Context {
    /// Creates a new single-threaded context.
    ///
    /// # Arguments
    ///
    /// * `io` - The I/O channel used by the context.
    pub fn new_single_threaded<Io>(io: Io) -> Self
    where
        Io: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        Self {
            id: ThreadId::default(),
            io: crate::io::Io::from_io(io),
            mode: Mode::St,
        }
    }

    pub(crate) fn from_io(io: Io) -> Self {
        Self {
            id: ThreadId::default(),
            io,
            mode: Mode::St,
        }
    }

    pub(crate) fn new_multi_threaded(
        id: ThreadId,
        io: Io,
        config: Arc<MtConfig>,
        builder: Arc<Mutex<ThreadBuilder>>,
    ) -> Self {
        Self {
            id: id.clone(),
            io,
            mode: Mode::Mt {
                threads: Threads::new(id, config, builder),
            },
        }
    }

    /// Returns `true` if the context is multi-threaded.
    pub fn is_multi_threaded(&self) -> bool {
        matches!(self.mode, Mode::Mt { .. })
    }

    /// Returns the thread ID.
    pub fn id(&self) -> &ThreadId {
        &self.id
    }

    /// Returns a mutable reference to the thread's I/O channel.
    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    /// Executes a collection of tasks provided with a context.
    ///
    /// If multi-threading is available, the tasks are load balanced across
    /// threads. Otherwise, they are executed sequentially.
    pub async fn map<'a, F, T, R, W>(
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
        match &mut self.mode {
            Mode::St => Ok(st::map(self, items, f).await),
            Mode::Mt { threads } => {
                let threads = threads.get(threads.concurrency()).await?;
                mt::map(threads, items, f, weight).await
            }
        }
    }

    /// Forks the thread and executes the provided closures concurrently.
    ///
    /// Implementations may not be able to fork, in which case the closures are
    /// executed sequentially.
    pub async fn join<'a, A, B, RA, RB>(&'a mut self, a: A, b: B) -> Result<(RA, RB), ContextError>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'static,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static,
    {
        match &mut self.mode {
            Mode::St => Ok(st::join(self, a, b).await),
            Mode::Mt { threads } => {
                let threads = threads.get(2).await?;
                mt::join(threads, a, b).await
            }
        }
    }

    /// Forks the thread and executes the provided closures concurrently,
    /// returning an error if one of the closures fails.
    ///
    /// This method is short circuiting, meaning that it returns as soon as one
    /// of the closures fails, potentially canceling the other.
    ///
    /// Implementations may not be able to fork, in which case the closures are
    /// executed sequentially.
    pub async fn try_join<'a, A, B, RA, RB, E>(
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
        match &mut self.mode {
            Mode::St => Ok(st::try_join(self, a, b).await),
            Mode::Mt { threads } => {
                let threads = threads.get(2).await?;
                mt::try_join(threads, a, b).await
            }
        }
    }
}

#[derive(Debug)]
enum Mode {
    /// Single-threaded.
    St,
    /// Multi-threaded.
    Mt { threads: Threads },
}

/// Error for [`Context`].
#[derive(Debug, thiserror::Error)]
#[error("context error: {kind}")]
pub struct ContextError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ContextError {
    #[allow(dead_code)]
    pub(crate) fn new<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        kind: ErrorKind,
        source: E,
    ) -> Self {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ErrorKind {
    Mux,
    Thread,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Mux => write!(f, "multiplexer error"),
            ErrorKind::Thread => write!(f, "thread error"),
        }
    }
}

impl From<SpawnError> for ContextError {
    fn from(err: SpawnError) -> Self {
        Self {
            kind: ErrorKind::Thread,
            source: Some(Box::new(err)),
        }
    }
}
