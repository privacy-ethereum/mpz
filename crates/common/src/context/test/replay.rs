//! Replay infrastructure for isolated benchmarking.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
};

use futures::{AsyncRead, AsyncWrite};

use crate::{
    context::Context,
    executor::{Executor, ExecutorBuilder},
    io::Io,
    mux::Mux,
};

use super::recording::RecordedMtData;

/// A duplex stream that replays recorded bytes on read and discards writes.
///
/// Used for replay-based isolated benchmarking where one party receives
/// pre-recorded messages without a real counterparty.
pub struct ReplayDuplex {
    /// Recorded bytes to replay.
    data: std::io::Cursor<Vec<u8>>,
}

impl ReplayDuplex {
    /// Creates a new replay duplex from recorded bytes.
    pub fn new(recorded: Vec<u8>) -> Self {
        Self {
            data: std::io::Cursor::new(recorded),
        }
    }
}

impl AsyncRead for ReplayDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        use std::io::Read;
        Poll::Ready(self.data.read(buf))
    }
}

impl AsyncWrite for ReplayDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Discard writes - just report success
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A simple mux that wraps a single replay stream.
struct SingleReplayMux {
    replay: Mutex<Option<ReplayDuplex>>,
    max_frame_length: Option<usize>,
}

impl SingleReplayMux {
    fn new(recorded: Vec<u8>, max_frame_length: Option<usize>) -> Self {
        Self {
            replay: Mutex::new(Some(ReplayDuplex::new(recorded))),
            max_frame_length,
        }
    }
}

impl Mux for SingleReplayMux {
    fn open(&self, id: &[u8]) -> Result<Io, std::io::Error> {
        // Only allow opening the root ID
        if id != [0] {
            return Err(std::io::Error::other("single replay mux only supports root ID"));
        }
        let replay = self
            .replay
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| std::io::Error::other("channel already opened"))?;
        if let Some(limit) = self.max_frame_length {
            Ok(Io::from_io_with_limit(replay, limit))
        } else {
            Ok(Io::from_io(replay))
        }
    }
}

/// Creates a single-threaded context that replays recorded bytes.
///
/// The context will read from the recorded bytes and discard all writes.
/// Use this for replay-based isolated benchmarking of a single party.
///
/// # Arguments
///
/// * `recorded` - The recorded bytes to replay.
/// * `max_frame_length` - Maximum frame size in bytes.
pub fn replay_st_context(recorded: Vec<u8>, max_frame_length: usize) -> Context {
    let mux = SingleReplayMux::new(recorded, Some(max_frame_length));
    Context::new(mux).unwrap()
}

// ============================================================================
// Multi-threaded replay infrastructure
// ============================================================================

/// A test mux that replays recorded data.
///
/// Provides channels that read from pre-recorded data and discard writes.
#[derive(Debug, Clone)]
struct ReplayTestMux {
    recorded: Arc<Mutex<RecordedMtData>>,
    max_frame_length: Option<usize>,
}

impl ReplayTestMux {
    /// Creates a new replay mux from recorded data.
    fn new(recorded: RecordedMtData, max_frame_length: Option<usize>) -> Self {
        Self {
            recorded: Arc::new(Mutex::new(recorded)),
            max_frame_length,
        }
    }
}

impl Mux for ReplayTestMux {
    fn open(&self, id: &[u8]) -> Result<Io, std::io::Error> {
        let recorded = self.recorded.clone();
        let max_frame_length = self.max_frame_length;
        let data = {
            let mut rec = recorded.lock().unwrap();
            rec.channels.remove(id).unwrap_or_default()
        };
        let replay = ReplayDuplex::new(data);
        if let Some(limit) = max_frame_length {
            Ok(Io::from_io_with_limit(replay, limit))
        } else {
            Ok(Io::from_io(replay))
        }
    }
}

/// Creates a multi-threaded context that replays recorded data.
///
/// The context will read from the recorded bytes and discard all writes.
/// Use this for replay-based isolated benchmarking of a single party in MT
/// mode.
///
/// # Arguments
///
/// * `recorded` - The recorded data to replay (per-channel).
pub fn replay_mt_context(recorded: RecordedMtData) -> Executor {
    let mux = ReplayTestMux::new(recorded, None);
    ExecutorBuilder::default().build(mux)
}

/// Creates a multi-threaded context that replays recorded data with a custom
/// frame length limit.
///
/// # Arguments
///
/// * `recorded` - The recorded data to replay (per-channel).
/// * `max_frame_length` - Maximum frame size in bytes.
pub fn replay_mt_context_with_limit(
    recorded: RecordedMtData,
    max_frame_length: usize,
) -> Executor {
    let mux = ReplayTestMux::new(recorded, Some(max_frame_length));
    ExecutorBuilder::default().build(mux)
}

/// Like [`replay_mt_context_with_limit`], but uses a custom worker spawn
/// callback (e.g. `web_spawn::spawn` on wasm) and a fixed concurrency level.
pub fn replay_mt_context_with_spawn_and_limit<F>(
    recorded: RecordedMtData,
    max_frame_length: usize,
    concurrency: usize,
    spawn: F,
) -> Executor
where
    F: Fn(Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let mux = ReplayTestMux::new(recorded, Some(max_frame_length));
    ExecutorBuilder::default()
        .num_threads(concurrency)
        .spawn(spawn)
        .build(mux)
}

