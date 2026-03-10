//! Basic test context helpers.

use crate::mux::test_framed_mux;
use futures::{AsyncRead, AsyncWrite};
use serio::channel::duplex;

use crate::{
    context::{Context, CustomSpawn, Multithread, SharedPool, SpawnError, StdSpawn},
    io::Io,
    mux::Mux,
};

/// Creates a single-threaded context with a custom frame limit.
///
/// # Arguments
///
/// * `io` - The I/O channel used by the context.
/// * `max_frame_length` - Maximum frame size in bytes.
pub(super) fn new_st_context_with_limit<I>(io: I, max_frame_length: usize) -> Context
where
    I: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    Context::from_io(Io::from_io_with_limit(io, max_frame_length))
}

/// Creates a pair of single-threaded contexts using memory I/O channels.
pub fn test_st_context(io_buffer: usize) -> (Context, Context) {
    let (io_0, io_1) = duplex(io_buffer);

    (
        Context::from_io(Io::from_channel(io_0)),
        Context::from_io(Io::from_channel(io_1)),
    )
}

/// Creates a default pool with 8 threads using `std::thread::spawn`.
fn default_pool() -> SharedPool {
    SharedPool::new(8, &mut StdSpawn).unwrap()
}

/// Creates a pair of multi-threaded contexts using multiplexed I/O channels.
pub fn test_mt_context(io_buffer: usize) -> (Multithread, Multithread) {
    let pool = default_pool();

    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    let mux_0: Box<dyn Mux + Send> = Box::new(mux_0);
    let mux_1: Box<dyn Mux + Send> = Box::new(mux_1);

    (
        Multithread::builder()
            .pool(pool.clone())
            .mux(mux_0)
            .build()
            .unwrap(),
        Multithread::builder()
            .pool(pool)
            .mux(mux_1)
            .build()
            .unwrap(),
    )
}

/// Creates a pair of multi-threaded contexts with a custom spawn handler.
///
/// This is useful for WASM environments where `std::thread::spawn` is not
/// available and a custom spawner like `web_spawn` is needed.
pub fn test_mt_context_with_spawn<F>(io_buffer: usize, spawn: F) -> (Multithread, Multithread)
where
    F: FnMut(Box<dyn FnOnce() + Send>) -> Result<(), SpawnError> + Clone + Send + 'static,
{
    let pool = SharedPool::new(8, &mut CustomSpawn(spawn)).unwrap();

    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    let mux_0: Box<dyn Mux + Send> = Box::new(mux_0);
    let mux_1: Box<dyn Mux + Send> = Box::new(mux_1);

    (
        Multithread::builder()
            .pool(pool.clone())
            .mux(mux_0)
            .build()
            .unwrap(),
        Multithread::builder()
            .pool(pool)
            .mux(mux_1)
            .build()
            .unwrap(),
    )
}

/// Creates a pair of multi-threaded contexts sharing a single pool.
///
/// Both sides reuse the same worker threads, which mirrors the intended
/// usage in resource-constrained environments like WASM.
pub fn test_mt_context_with_shared_pool(io_buffer: usize) -> (Multithread, Multithread) {
    let pool = default_pool();

    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    let mux_0: Box<dyn Mux + Send> = Box::new(mux_0);
    let mux_1: Box<dyn Mux + Send> = Box::new(mux_1);

    (
        Multithread::builder()
            .pool(pool.clone())
            .mux(mux_0)
            .build()
            .unwrap(),
        Multithread::builder()
            .pool(pool)
            .mux(mux_1)
            .build()
            .unwrap(),
    )
}

/// Creates a pair of multi-threaded contexts with a custom spawn handler and
/// concurrency.
///
/// Like [`test_mt_context_with_spawn`], but allows configuring the maximum
/// concurrency level (number of worker threads) per context.
pub fn test_mt_context_with_concurrency<F>(
    io_buffer: usize,
    concurrency: usize,
    spawn: F,
) -> (Multithread, Multithread)
where
    F: FnMut(Box<dyn FnOnce() + Send>) -> Result<(), SpawnError> + Clone + Send + 'static,
{
    let pool = SharedPool::new(concurrency, &mut CustomSpawn(spawn)).unwrap();

    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    let mux_0: Box<dyn Mux + Send> = Box::new(mux_0);
    let mux_1: Box<dyn Mux + Send> = Box::new(mux_1);

    (
        Multithread::builder()
            .pool(pool.clone())
            .mux(mux_0)
            .build()
            .unwrap(),
        Multithread::builder()
            .pool(pool)
            .mux(mux_1)
            .build()
            .unwrap(),
    )
}
