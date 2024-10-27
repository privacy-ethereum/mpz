use core::fmt;

use async_trait::async_trait;

use scoped_futures::ScopedBoxFuture;
use serio::{IoSink, IoStream};

use crate::ThreadId;

/// An error for types that implement [`Context`].
#[derive(Debug, thiserror::Error)]
#[error("context error: {kind}")]
pub struct ContextError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ContextError {
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

/// A thread context.
#[async_trait]
pub trait Context: Send + Sync {
    /// I/O channel used by the thread.
    type Io: IoSink + IoStream + Send + Unpin + 'static;

    /// Returns the thread ID.
    fn id(&self) -> &ThreadId;

    /// Returns the maximum available concurrency.
    fn max_concurrency(&self) -> usize;

    /// Returns a mutable reference to the thread's I/O channel.
    fn io_mut(&mut self) -> &mut Self::Io;

    /// Forks the thread and executes the provided closures concurrently.
    ///
    /// Implementations may not be able to fork, in which case the closures are
    /// executed sequentially.
    async fn join<'a, A, B, RA, RB>(&'a mut self, a: A, b: B) -> Result<(RA, RB), ContextError>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'static,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'static,
        RA: Send + 'static,
        RB: Send + 'static;

    /// Forks the thread and executes the provided closures concurrently,
    /// returning an error if one of the closures fails.
    ///
    /// This method is short circuiting, meaning that it returns as soon as one
    /// of the closures fails, potentially canceling the other.
    ///
    /// Implementations may not be able to fork, in which case the closures are
    /// executed sequentially.
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
        E: Send + 'static;
}
