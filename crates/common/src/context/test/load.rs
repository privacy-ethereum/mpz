//! Load tests for the bounded thread pool and bounded stream opening.
//!
//! These exercise the guarantees from the executor/global-pool refactor
//! (issue #403):
//!
//! 1. A [`ThreadPool`] spawns a fixed number of worker threads, no matter how
//!    much work is thrown at it. Sub-tasks are multiplexed onto that fixed
//!    pool rather than each spawning its own thread.
//! 2. [`Context::map`] opens at most `concurrency_limit` I/O channels (mux
//!    streams) at any instant, even when given far more items than that. This
//!    is what keeps a mux from exceeding its maximum stream limit.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    task::{Context as TaskContext, Poll},
};

use futures::{AsyncRead, AsyncWrite, executor::block_on, future::poll_fn};
use rstest::rstest;

use crate::{
    io::Io,
    mux::Mux,
    session::{Session, SessionBuilder},
    thread_pool::ThreadPool,
};

/// Shared open-stream accounting for [`CountingMux`].
#[derive(Default)]
struct Counters {
    /// Number of channels currently open (opened but not yet dropped).
    live: AtomicUsize,
    /// High-water mark of `live` observed across the run.
    peak: AtomicUsize,
    /// Total number of `open` calls.
    opened: AtomicUsize,
}

/// A throwaway channel transport that decrements the live stream count when
/// dropped, letting the mux observe when a channel is closed.
///
/// The load tests never perform I/O over these channels, so reads report EOF
/// and writes are discarded.
struct TrackedTransport {
    counters: Arc<Counters>,
}

impl Drop for TrackedTransport {
    fn drop(&mut self) {
        self.counters.live.fetch_sub(1, SeqCst);
    }
}

impl AsyncRead for TrackedTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
}

impl AsyncWrite for TrackedTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A mux that hands out throwaway channels while tracking how many are open at
/// once.
struct CountingMux {
    counters: Arc<Counters>,
}

impl Mux for CountingMux {
    fn open(&self, _id: &[u8]) -> Result<Io, io::Error> {
        self.counters.opened.fetch_add(1, SeqCst);
        let live = self.counters.live.fetch_add(1, SeqCst) + 1;
        self.counters.peak.fetch_max(live, SeqCst);

        Ok(Io::from_io(TrackedTransport {
            counters: self.counters.clone(),
        }))
    }
}

/// Whether the session multiplexes work onto a thread pool or runs sub-tasks
/// cooperatively on the caller's future.
#[derive(Clone, Copy)]
enum ExecMode {
    Pooled,
    Cooperative,
}

fn session_with_mux(mode: ExecMode, mux: CountingMux, limit: usize) -> Session {
    let builder = match mode {
        ExecMode::Pooled => {
            SessionBuilder::default().pool(ThreadPool::builder().num_threads(4).build().unwrap())
        }
        ExecMode::Cooperative => SessionBuilder::default().cooperative(),
    };
    builder.concurrency_limit(limit).build(mux).unwrap()
}

/// `map` over far more items than the concurrency limit must never have more
/// than `limit` sub-channels open at once, regardless of execution mode.
#[rstest]
#[case::pooled(ExecMode::Pooled)]
#[case::cooperative(ExecMode::Cooperative)]
fn test_map_bounds_open_streams(#[case] mode: ExecMode) {
    const LIMIT: usize = 8;
    const ITEMS: usize = 256;

    let counters = Arc::new(Counters::default());
    let mux = CountingMux {
        counters: counters.clone(),
    };
    let session = session_with_mux(mode, mux, LIMIT);
    let mut ctx = session.new_context().unwrap();

    // Items are released only once a full window of `LIMIT` sub-tasks has
    // opened its channel, forcing the peak to actually reach the limit. The
    // counter is monotonic, so later waves pass the gate immediately and never
    // deadlock.
    let arrived = Arc::new(AtomicUsize::new(0));
    let threshold = LIMIT.min(ITEMS);

    let items: Vec<usize> = (0..ITEMS).collect();
    let results = block_on(ctx.map(items, move |_ctx, x| {
        let arrived = arrived.clone();
        Box::pin(async move {
            arrived.fetch_add(1, SeqCst);
            // Park until a full window has arrived, re-waking to re-check.
            poll_fn(|cx| {
                if arrived.load(SeqCst) >= threshold {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            x * 2
        })
    }))
    .unwrap();

    let expected: Vec<usize> = (0..ITEMS).map(|x| x * 2).collect();
    assert_eq!(results, expected, "all items processed in input order");

    // One open per item, plus the parent context's own channel.
    assert_eq!(
        counters.opened.load(SeqCst),
        ITEMS + 1,
        "every item should still open its own channel"
    );

    // Every channel `map` opened must have been dropped by the time it
    // returns; only the parent context's own channel (still held by `ctx`)
    // remains open.
    assert_eq!(
        counters.live.load(SeqCst),
        1,
        "map sub-channels should all be closed, leaving only the parent"
    );

    // Dropping the context closes the last channel.
    drop(ctx);
    assert_eq!(counters.live.load(SeqCst), 0, "no channels leaked");

    // The crux: the parent channel stays open for the duration (+1), and at
    // most `LIMIT` item channels are open concurrently. The gate guarantees a
    // full window overlaps, so the peak reaches but never exceeds the bound.
    let peak = counters.peak.load(SeqCst);
    assert!(
        peak <= LIMIT + 1,
        "open streams must stay bounded: peak {peak} exceeded limit {LIMIT} (+1 parent)"
    );
    assert!(
        peak >= LIMIT,
        "expected the concurrency window to fill (peak {peak}, limit {LIMIT}); test is not exercising overlap"
    );
}

/// A thread pool runs an arbitrary amount of work on a fixed number of worker
/// threads. The spawn callback must fire exactly `num_threads` times and never
/// again, no matter how many sub-tasks are dispatched.
#[test]
fn test_thread_pool_thread_count_is_bounded() {
    const NUM_THREADS: usize = 4;
    const ITEMS: usize = 1024;

    let spawned = Arc::new(AtomicUsize::new(0));
    let pool = {
        let spawned = spawned.clone();
        ThreadPool::builder()
            .num_threads(NUM_THREADS)
            .spawn(move |f| {
                spawned.fetch_add(1, SeqCst);
                std::thread::Builder::new().spawn(f).map(drop)
            })
            .build()
            .unwrap()
    };

    assert_eq!(
        spawned.load(SeqCst),
        NUM_THREADS,
        "pool should start exactly its configured worker count"
    );

    let counters = Arc::new(Counters::default());
    let mux = CountingMux {
        counters: counters.clone(),
    };
    let session = SessionBuilder::default().pool(pool).build(mux).unwrap();
    let mut ctx = session.new_context().unwrap();

    // Dispatch far more sub-tasks than there are worker threads.
    let items: Vec<usize> = (0..ITEMS).collect();
    let results = block_on(ctx.map(items, |_ctx, x| Box::pin(async move { x + 1 }))).unwrap();

    let expected: Vec<usize> = (0..ITEMS).map(|x| x + 1).collect();
    assert_eq!(results, expected, "all sub-tasks completed");

    // The whole point: dispatching 1024 sub-tasks did not spawn 1024 threads.
    assert_eq!(
        spawned.load(SeqCst),
        NUM_THREADS,
        "no additional threads should be spawned under load"
    );
}
