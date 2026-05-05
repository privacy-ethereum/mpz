//! Work-stealing async executor.
//!
//! This module provides a work-stealing threadpool executor that integrates
//! with the MPC task model. Each task is assigned a deterministic [`ContextId`]
//! and owns its own I/O channel, allowing tasks to be freely migrated between
//! worker threads while maintaining deterministic execution order for I/O.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use async_task::{Runnable, Task};
use crossbeam_deque::{Injector, Steal, Stealer, Worker};

use crate::{Context, ContextId, io::Io, mux::Mux};

/// A work-stealing async executor.
#[derive(Debug)]
pub struct Executor {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    /// Global task queue for new tasks and cross-thread wakeups.
    injector: Injector<Runnable>,

    /// Stealers for each worker's local queue.
    stealers: Vec<Stealer<Runnable>>,

    /// Number of active workers (for parking/unparking).
    active: AtomicUsize,

    /// Shutdown flag.
    shutdown: AtomicBool,

    /// Multiplexer for creating I/O channels.
    mux: Arc<dyn Mux + Send + Sync>,

    /// Namespace prefix applied to all contexts created by this executor.
    prefix: ContextId,

    /// Counter handed out to each new context, ensuring uniqueness.
    next_context: AtomicU32,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("stealers", &self.stealers.len())
            .field("shutdown", &self.shutdown)
            .finish_non_exhaustive()
    }
}

/// A worker spawn callback.
///
/// Receives a worker entry-point and dispatches it on a thread (or
/// platform-equivalent, e.g. `web_spawn::spawn` on wasm).
pub type SpawnFn =
    Box<dyn Fn(Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error> + Send + Sync>;

/// Builder for [`Executor`].
pub struct ExecutorBuilder {
    num_threads: usize,
    prefix: ContextId,
    spawn: SpawnFn,
}

impl std::fmt::Debug for ExecutorBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutorBuilder")
            .field("num_threads", &self.num_threads)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl Default for ExecutorBuilder {
    fn default() -> Self {
        Self {
            num_threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            prefix: ContextId::from_prefix([]),
            spawn: Box::new(default_spawn),
        }
    }
}

fn default_spawn(f: Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error> {
    std::thread::Builder::new()
        .name("mpz-executor-worker".to_string())
        .spawn(f)
        .map(drop)
}

impl ExecutorBuilder {
    /// Sets the number of worker threads.
    pub fn num_threads(mut self, n: usize) -> Self {
        self.num_threads = n;
        self
    }

    /// Sets a namespace prefix applied to all contexts created by the
    /// executor.
    ///
    /// Useful when several sub-protocols share a mux and need to be kept in
    /// disjoint ID spaces.
    pub fn prefix(mut self, prefix: impl AsRef<[u8]>) -> Self {
        self.prefix = ContextId::from_prefix(prefix);
        self
    }

    /// Sets a custom worker spawn callback.
    ///
    /// Defaults to `std::thread::spawn`. Useful on platforms without OS
    /// threads (e.g. wasm32 where workers must be created via
    /// `web_spawn::spawn`).
    pub fn spawn<F>(mut self, spawn: F) -> Self
    where
        F: Fn(Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error>
            + Send
            + Sync
            + 'static,
    {
        self.spawn = Box::new(spawn);
        self
    }

    /// Builds the executor with the given multiplexer.
    pub fn build<M: Mux + Send + Sync + 'static>(self, mux: M) -> Executor {
        let injector = Injector::new();

        // Create local worker queues and their stealers.
        let workers: Vec<Worker<Runnable>> =
            (0..self.num_threads).map(|_| Worker::new_fifo()).collect();

        let stealers: Vec<Stealer<Runnable>> = workers.iter().map(|w| w.stealer()).collect();

        let inner = Arc::new(Inner {
            injector,
            stealers,
            active: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
            mux: Arc::new(mux),
            prefix: self.prefix,
            next_context: AtomicU32::new(0),
        });

        // Spawn worker threads via the configured spawn callback.
        for (index, local) in workers.into_iter().enumerate() {
            let inner = inner.clone();
            (self.spawn)(Box::new(move || worker_loop(inner, local, index)))
                .expect("failed to spawn worker thread");
        }

        Executor { inner }
    }
}

/// Worker thread loop.
fn worker_loop(inner: Arc<Inner>, local: Worker<Runnable>, index: usize) {
    inner.active.fetch_add(1, Ordering::SeqCst);

    while !inner.shutdown.load(Ordering::Relaxed) {
        if let Some(runnable) = find_task(&inner, &local, index) {
            // Poll the task once. If it returns Pending, the waker will
            // reschedule it; if it completes, we're done with the task.
            runnable.run();
        } else {
            // No work available - yield to avoid busy-spinning.
            std::thread::yield_now();
        }
    }

    inner.active.fetch_sub(1, Ordering::SeqCst);
}

/// Finds a task to execute using work-stealing.
fn find_task(inner: &Inner, local: &Worker<Runnable>, index: usize) -> Option<Runnable> {
    // 1. Local queue (fast path, cache-friendly).
    if let Some(runnable) = local.pop() {
        return Some(runnable);
    }

    // 2. Global injector queue.
    loop {
        match inner.injector.steal_batch_and_pop(local) {
            Steal::Success(runnable) => return Some(runnable),
            Steal::Empty => break,
            Steal::Retry => continue,
        }
    }

    // 3. Steal from other workers.
    let num_stealers = inner.stealers.len();
    for i in 1..num_stealers {
        let victim = (index + i) % num_stealers;
        loop {
            match inner.stealers[victim].steal_batch_and_pop(local) {
                Steal::Success(runnable) => return Some(runnable),
                Steal::Empty => break,
                Steal::Retry => continue,
            }
        }
    }

    None
}

impl Executor {
    /// Creates a new builder.
    pub fn builder() -> ExecutorBuilder {
        ExecutorBuilder::default()
    }

    /// Spawns a new task on the executor.
    pub fn spawn<F>(&self, future: F) -> Task<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        spawn_on(&self.inner, future)
    }

    /// Opens an I/O channel for the given context ID.
    pub fn open_io(&self, id: &[u8]) -> Result<Io, std::io::Error> {
        self.inner.mux.open(id)
    }

    /// Shuts down the executor.
    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
    }

    /// Returns `true` if the executor has been shut down.
    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }

    /// Creates a new context.
    ///
    /// Each context produced by an executor is given a distinct ID under the
    /// executor's configured prefix.
    pub fn new_context(&self) -> Result<Context, std::io::Error> {
        let index = self.inner.next_context.fetch_add(1, Ordering::Relaxed);
        let id = self.inner.prefix.child(index);
        let io = self.inner.mux.open(id.as_ref())?;
        Ok(Context::with_executor(
            id,
            io,
            self.inner.mux.clone(),
            self.inner.clone(),
        ))
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Spawns a future on the given executor inner.
pub(crate) fn spawn_on<F>(inner: &Arc<Inner>, future: F) -> Task<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let inner = Arc::clone(inner);
    let schedule = move |runnable: Runnable| inner.injector.push(runnable);
    let (runnable, task) = async_task::spawn(future, schedule);
    runnable.schedule();
    task
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::test_framed_mux;
    use serio::{SinkExt, StreamExt};

    #[test]
    fn test_executor_spawn() {
        let (mux_a, _mux_b) = test_framed_mux(1024);
        let executor = Executor::builder().num_threads(2).build(mux_a);

        let task = executor.spawn(async { 42 });
        let result = futures::executor::block_on(task);

        assert_eq!(result, 42);

        executor.shutdown();
    }

    #[test]
    fn test_executor_map() {
        let (mux_a, _mux_b) = test_framed_mux(1024);
        let executor = Executor::builder().num_threads(2).build(mux_a);

        let mut ctx = executor.new_context().unwrap();

        let items = vec![1, 2, 3, 4, 5];
        let results =
            futures::executor::block_on(ctx.map(items, |_ctx, x| Box::pin(async move { x * 2 })));

        assert_eq!(results.unwrap(), vec![2, 4, 6, 8, 10]);

        executor.shutdown();
    }

    #[test]
    fn test_executor_join() {
        let (mux_a, _mux_b) = test_framed_mux(1024);
        let executor = Executor::builder().num_threads(2).build(mux_a);

        let mut ctx = executor.new_context().unwrap();

        let result = futures::executor::block_on(ctx.join(
            |_ctx| Box::pin(async move { 1 + 1 }),
            |_ctx| Box::pin(async move { 2 + 2 }),
        ));

        assert_eq!(result.unwrap(), (2, 4));

        executor.shutdown();
    }

    #[test]
    fn test_executor_io() {
        // Test that I/O works between two executors (simulating two parties).
        let (mux_a, mux_b) = test_framed_mux(1024);

        let executor_a = Executor::builder().num_threads(2).build(mux_a);
        let executor_b = Executor::builder().num_threads(2).build(mux_b);

        // Party A sends, Party B receives.
        let task_a = {
            let id = ContextId::new(1);
            let mut io = executor_a.open_io(id.as_ref()).unwrap();

            executor_a.spawn(async move {
                io.send(42u32).await.unwrap();
                io.send(123u32).await.unwrap();
            })
        };

        let task_b = {
            let id = ContextId::new(1);
            let mut io = executor_b.open_io(id.as_ref()).unwrap();

            executor_b.spawn(async move {
                let val1: u32 = io.next().await.unwrap().unwrap();
                let val2: u32 = io.next().await.unwrap().unwrap();
                (val1, val2)
            })
        };

        let ((), (val1, val2)) = futures::executor::block_on(futures::future::join(task_a, task_b));

        assert_eq!(val1, 42);
        assert_eq!(val2, 123);

        executor_a.shutdown();
        executor_b.shutdown();
    }

    #[test]
    fn test_executor_map_with_io() {
        // Test that map works with I/O between two parties.
        let (mux_a, mux_b) = test_framed_mux(1024);

        let executor_a = Executor::builder().num_threads(4).build(mux_a);
        let executor_b = Executor::builder().num_threads(4).build(mux_b);

        let mut ctx_a = executor_a.new_context().unwrap();
        let mut ctx_b = executor_b.new_context().unwrap();

        let items_a = vec![1u32, 2, 3, 4];
        let items_b = vec![10u32, 20, 30, 40];

        // Party A sends each item, Party B receives and returns sum.
        let task_a = ctx_a.map(items_a, |ctx, x| {
            Box::pin(async move {
                ctx.io_mut().send(x).await.unwrap();
            })
        });

        let task_b = ctx_b.map(items_b, |ctx, x| {
            Box::pin(async move {
                let received: u32 = ctx.io_mut().next().await.unwrap().unwrap();
                received + x
            })
        });

        let (results_a, results_b) =
            futures::executor::block_on(futures::future::join(task_a, task_b));

        assert!(results_a.is_ok());
        let results_b = results_b.unwrap();

        // Each B task should receive the corresponding A value and add it to B's value.
        assert_eq!(results_b, vec![11, 22, 33, 44]);

        executor_a.shutdown();
        executor_b.shutdown();
    }
}
