use async_trait::async_trait;

use scoped_futures::ScopedBoxFuture;
use serio::{IoSink, IoStream};

use crate::ThreadId;

/// A thread context.
#[async_trait]
pub trait Context: Send {
    /// The type of I/O channel used by the thread.
    type Io: IoSink + IoStream + Send + Unpin + 'static;

    /// Returns the thread ID.
    fn id(&self) -> &ThreadId;

    /// Returns a mutable reference to the thread's I/O channel.
    fn io_mut(&mut self) -> &mut Self::Io;

    /// Forks the thread and executes the provided closures concurrently.
    ///
    /// Implementations may not be able to fork, in which case the closures are executed
    /// sequentially.
    async fn join<'a, A, B, RA, RB>(&'a mut self, a: A, b: B) -> (RA, RB)
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RA> + Send + 'a,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, RB> + Send + 'a,
        RA: Send + 'a,
        RB: Send + 'a;

    /// Forks the thread and executes the provided closures concurrently, returning an error
    /// if one of the closures fails.
    ///
    /// This method is short circuiting, meaning that it returns as soon as one of the closures
    /// fails, potentially canceling the other.
    ///
    /// Implementations may not be able to fork, in which case the closures are executed
    /// sequentially.
    async fn try_join<'a, A, B, RA, RB, E>(&'a mut self, a: A, b: B) -> Result<(RA, RB), E>
    where
        A: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RA, E>> + Send + 'a,
        B: for<'b> FnOnce(&'b mut Self) -> ScopedBoxFuture<'a, 'b, Result<RB, E>> + Send + 'a,
        RA: Send + 'a,
        RB: Send + 'a,
        E: Send + 'a;
}
