use std::{rc::Rc, sync::Arc};

use async_executor::LocalExecutor;

use super::spawn::{Spawn, SpawnError};

/// A `Send` closure that spawns work on a thread-local `LocalExecutor`.
///
/// The closure crosses the thread boundary (hence `Send`), but the futures
/// it spawns on the executor need not be `Send`.
pub(crate) type TaskFn = Box<dyn for<'a> FnOnce(&LocalExecutor<'a>) + Send>;

/// Shared senders for dispatching tasks to pool threads.
pub(crate) type TaskSenders = Arc<Vec<async_channel::Sender<TaskFn>>>;

/// A pool of worker threads, each running a local async executor.
///
/// Unlike a shared work-stealing executor, each thread has its own
/// `LocalExecutor`. Tasks are dispatched to specific threads via channels.
/// This avoids requiring `Send` on spawned futures while still allowing
/// cooperative async scheduling within each thread.
pub(crate) struct SharedPool {
    senders: TaskSenders,
}

impl SharedPool {
    /// Creates a new pool with `num_threads` worker threads.
    ///
    /// Each worker thread runs a `LocalExecutor` that processes tasks received
    /// via an async channel. Dropping the pool closes all channels, causing
    /// workers to exit.
    pub(crate) fn new(num_threads: usize, spawn: &mut dyn Spawn) -> Result<Self, SpawnError> {
        if num_threads == 0 {
            return Err(SpawnError::new("pool requires at least 1 worker thread"));
        }

        let mut senders = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let (tx, rx) = async_channel::unbounded::<TaskFn>();

            spawn.spawn(Box::new(move || {
                // Rc breaks the self-referential borrow: run() borrows
                // through one Rc handle while the async block captures another.
                let local_ex = Rc::new(LocalExecutor::new());
                let ex = Rc::clone(&local_ex);
                pollster::block_on(local_ex.run(async move {
                    while let Ok(task_fn) = rx.recv().await {
                        task_fn(&ex);
                    }
                }));
            }))?;

            senders.push(tx);
        }

        Ok(Self {
            senders: Arc::new(senders),
        })
    }

    /// Returns shared senders for dispatching tasks to pool threads.
    pub(crate) fn senders(&self) -> &TaskSenders {
        &self.senders
    }
}

impl std::fmt::Debug for SharedPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedPool").finish_non_exhaustive()
    }
}
