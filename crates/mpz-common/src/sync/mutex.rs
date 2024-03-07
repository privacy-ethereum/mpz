//! Synchronized mutex.

use std::sync::{LockResult, Mutex as StdMutex, MutexGuard};

use crate::{context::Context, sync::Syncer};

use super::SyncError;

/// A mutex which synchronizes exclusive access to a resource across logical threads.
///
/// There are two configurations for a mutex, either as a leader or as a follower.
///
/// **Leader**
///
/// A leader mutex is the authority on the order in which threads can acquire a lock. When a
/// thread acquires a lock, it broadcasts a message to all follower mutexes, which then enforce
/// that this order is preserved.
///
/// **Follower**
///
/// A follower mutex waits for messages from the leader mutex to inform it of the order in which
/// threads can acquire a lock.
#[derive(Debug)]
pub struct Mutex<T> {
    inner: StdMutex<T>,
    syncer: Syncer,
}

impl<T> Mutex<T> {
    /// Creates a new leader mutex.
    ///
    /// # Arguments
    ///
    /// * `value` - The value protected by the mutex.
    pub fn new_leader(value: T) -> Self {
        Self {
            inner: StdMutex::new(value),
            syncer: Syncer::new_leader(),
        }
    }

    /// Creates a new follower mutex.
    ///
    /// # Arguments
    ///
    /// * `value` - The value protected by the mutex.
    pub fn new_follower(value: T) -> Self {
        Self {
            inner: StdMutex::new(value),
            syncer: Syncer::new_follower(),
        }
    }

    /// Returns a lock on the mutex.
    pub async fn lock<Ctx: Context>(&self, ctx: &mut Ctx) -> Result<MutexGuard<'_, T>, MutexError> {
        self.syncer
            .sync(ctx.io_mut(), || self.inner.lock())
            .await?
            .map_err(|_| MutexError::Poisoned)
    }

    /// Returns the inner value, consuming the mutex.
    pub fn into_inner(self) -> LockResult<T> {
        self.inner.into_inner()
    }
}

/// An error returned when a mutex operation fails.
#[derive(Debug, thiserror::Error)]
pub enum MutexError {
    /// A synchronization error occurred.
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
    /// The mutex was poisoned.
    #[error("mutex was poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn test_mutex_st() {
        let leader_mutex = Arc::new(Mutex::new_leader(()));
        let follower_mutex = Arc::new(Mutex::new_follower(()));

        let (mut ctx_a, mut ctx_b) = crate::executor::test_st_executor(8);

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
