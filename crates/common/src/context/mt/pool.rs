use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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
///
/// Cloning a `SharedPool` shares the same underlying worker threads.
/// This allows multiple [`Multithread`](super::Multithread) instances to
/// reuse the same pool, which is important in resource-constrained
/// environments like WASM where each worker is an expensive Web Worker.
#[derive(Clone)]
pub struct SharedPool {
    senders: TaskSenders,
    // Shared flag that signals workers to stop when all senders are dropped.
    _shutdown: Arc<ShutdownFlag>,
}

/// Sets the shutdown flag on drop, signaling worker threads to exit.
struct ShutdownFlag {
    flag: Arc<AtomicBool>,
}

impl Drop for ShutdownFlag {
    fn drop(&mut self) {
        self.flag.store(true, Ordering::Release);
    }
}

impl SharedPool {
    /// Creates a new pool with `num_threads` worker threads.
    ///
    /// Each worker thread runs a `LocalExecutor` that processes tasks received
    /// via a channel. The worker loop uses synchronous `try_recv` to drain the
    /// channel, then ticks the executor to drive spawned async tasks. This
    /// avoids relying on async waker propagation through `pollster`, which
    /// does not work reliably in WASM Web Workers.
    pub fn new(num_threads: usize, spawn: &mut dyn Spawn) -> Result<Self, SpawnError> {
        if num_threads == 0 {
            return Err(SpawnError::new("pool requires at least 1 worker thread"));
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let mut senders = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let (tx, rx) = async_channel::unbounded::<TaskFn>();
            let shutdown = shutdown.clone();

            spawn.spawn(Box::new(move || {
                let local_ex = LocalExecutor::new();

                // Spin loop: drain incoming task closures, tick the executor,
                // and park briefly when idle. Each TaskFn spawns an async task
                // on the LocalExecutor; ticking drives those tasks forward.
                loop {
                    // Drain all pending task submissions.
                    let mut received = false;
                    while let Ok(task_fn) = rx.try_recv() {
                        task_fn(&local_ex);
                        received = true;
                    }

                    // Tick executor to drive spawned async tasks.
                    while local_ex.try_tick() {
                        received = true;
                    }

                    // If channel is closed and no tasks remain, exit.
                    if rx.is_closed() && local_ex.is_empty() {
                        break;
                    }

                    if shutdown.load(Ordering::Acquire) && local_ex.is_empty() {
                        break;
                    }

                    // Park briefly to avoid busy-spinning when idle.
                    if !received {
                        std::thread::park_timeout(std::time::Duration::from_millis(1));
                    }
                }
            }))?;

            senders.push(tx);
        }

        Ok(Self {
            senders: Arc::new(senders),
            _shutdown: Arc::new(ShutdownFlag { flag: shutdown }),
        })
    }

    /// Returns the number of worker threads in the pool.
    pub fn num_threads(&self) -> usize {
        self.senders.len()
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
