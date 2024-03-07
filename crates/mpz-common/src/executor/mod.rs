//! Executors.

mod st;

pub use st::STExecutor;

#[cfg(any(test, feature = "test-utils"))]
mod test_utils {
    use serio::channel::{duplex, MemoryDuplex};

    use super::*;

    /// Creates a pair of single-threaded executors with memory I/O channels.
    pub fn test_st_executor(
        io_buffer: usize,
    ) -> (STExecutor<MemoryDuplex>, STExecutor<MemoryDuplex>) {
        let (io_0, io_1) = duplex(io_buffer);

        (STExecutor::new(io_0), STExecutor::new(io_1))
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::*;
