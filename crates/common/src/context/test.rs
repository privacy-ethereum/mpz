use serio::channel::duplex;
use uid_mux::test_utils::test_framed_mux;

use crate::{
    context::{Context, Multithread},
    io::Io,
    mux::Mux,
};

/// Creates a pair of single-threaded contexts using memory I/O channels.
pub fn test_st_context(io_buffer: usize) -> (Context, Context) {
    let (io_0, io_1) = duplex(io_buffer);

    (
        Context::from_io(Io::from_channel(io_0)),
        Context::from_io(Io::from_channel(io_1)),
    )
}

/// Creates a pair of multi-threaded contexts using multiplexed I/O channels.
pub fn test_mt_context(io_buffer: usize) -> (Multithread, Multithread) {
    let (mux_0, mux_1) = test_framed_mux(io_buffer);

    let mux_0: Box<dyn Mux + Send> = Box::new(mux_0);
    let mux_1: Box<dyn Mux + Send> = Box::new(mux_1);

    (
        Multithread::builder().mux_internal(mux_0).build().unwrap(),
        Multithread::builder().mux_internal(mux_1).build().unwrap(),
    )
}
