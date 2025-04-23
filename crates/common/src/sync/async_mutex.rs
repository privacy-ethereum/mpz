//! Synchronized async mutex.

use pollster::FutureExt;
use tokio::sync::{Mutex as TokioMutex, MutexGuard};

use crate::{
    context::Context,
    sync::{AsyncSyncer, MutexError},
};

/// A mutex which synchronizes exclusive access to a resource across logical
/// threads.
///
/// There are two configurations for a mutex, either as a leader or as a
/// follower.
///
/// **Leader**
///
/// A leader mutex is the authority on the order in which threads can acquire a
/// lock. When a thread acquires a lock, it broadcasts a message to all follower
/// mutexes, which then enforce that this order is preserved.
///
/// **Follower**
///
/// A follower mutex waits for messages from the leader mutex to inform it of
/// the order in which threads can acquire a lock.
#[derive(Debug)]
pub struct AsyncMutex<T> {
    inner: TokioMutex<T>,
    syncer: AsyncSyncer,
}

impl<T> AsyncMutex<T> {
    /// Creates a new leader mutex.
    ///
    /// # Arguments
    ///
    /// * `value` - The value protected by the mutex.
    pub fn new_leader(value: T) -> Self {
        Self {
            inner: TokioMutex::new(value),
            syncer: AsyncSyncer::new_leader(),
        }
    }

    /// Creates a new follower mutex.
    ///
    /// # Arguments
    ///
    /// * `value` - The value protected by the mutex.
    pub fn new_follower(value: T) -> Self {
        Self {
            inner: TokioMutex::new(value),
            syncer: AsyncSyncer::new_follower(),
        }
    }

    /// Returns a lock on the mutex.
    pub async fn lock(&self, ctx: &mut Context) -> Result<MutexGuard<'_, T>, MutexError> {
        self.syncer
            .sync(ctx.io_mut(), self.inner.lock())
            .await
            .map_err(MutexError::from)
    }

    /// Returns an unsynchronized blocking lock on the mutex.
    ///
    /// # Warning
    ///
    /// Do not use this method unless you are certain that the way you're
    /// mutating the state does not require synchronization. Also, don't
    /// hold this lock across await points it will cause deadlocks.
    pub fn blocking_lock_unsync(&self) -> MutexGuard<'_, T> {
        self.inner.lock().block_on()
    }

    /// Returns the inner value, consuming the mutex.
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn test_async_mutex() {
        let leader_mutex = Arc::new(AsyncMutex::new_leader(()));
        let follower_mutex = Arc::new(AsyncMutex::new_follower(()));

        let (mut ctx_a, mut ctx_b) = crate::context::test_st_context(8);

        futures::executor::block_on(async {
            futures::join!(
                async {
                    drop(leader_mutex.lock(&mut ctx_a).await.unwrap());
                    drop(leader_mutex.lock(&mut ctx_a).await.unwrap());
                    drop(leader_mutex.lock(&mut ctx_a).await.unwrap());
                },
                async {
                    drop(follower_mutex.lock(&mut ctx_b).await.unwrap());
                    drop(follower_mutex.lock(&mut ctx_b).await.unwrap());
                    drop(follower_mutex.lock(&mut ctx_b).await.unwrap());
                },
            );
        });
    }
}
