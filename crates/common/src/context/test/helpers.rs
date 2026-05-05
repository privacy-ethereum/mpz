//! Basic test context helpers.

use crate::{
    context::Context,
    executor::{Executor, ExecutorBuilder},
    mux::test_framed_mux,
};

/// Creates a pair of single-threaded contexts using multiplexed I/O channels.
pub fn test_st_context(io_buffer: usize) -> (Context, Context) {
    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    (Context::new(mux_0).unwrap(), Context::new(mux_1).unwrap())
}

/// Creates a pair of multi-threaded executors sharing multiplexed I/O channels.
pub fn test_mt_context(io_buffer: usize) -> (Executor, Executor) {
    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    (
        ExecutorBuilder::default().build(mux_0),
        ExecutorBuilder::default().build(mux_1),
    )
}

/// Like [`test_mt_context`], but uses a custom worker spawn callback (e.g.
/// `web_spawn::spawn` on wasm).
pub fn test_mt_context_with_spawn<F>(io_buffer: usize, spawn: F) -> (Executor, Executor)
where
    F: Fn(Box<dyn FnOnce() + Send + 'static>) -> Result<(), std::io::Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    (
        ExecutorBuilder::default().spawn(spawn.clone()).build(mux_0),
        ExecutorBuilder::default().spawn(spawn).build(mux_1),
    )
}
