//! Executors.

#[cfg(any(test, feature = "test-utils"))]
pub mod dummy;
pub mod mt;
pub mod st;

#[cfg(any(test, feature = "test-utils"))]
mod test_utils {
    use super::{
        mt::{MTConfig, MTExecutor},
        st::STExecutor,
    };
    use serio::channel::{duplex, MemoryDuplex};
    use uid_mux::test_utils::{test_framed_mux, TestFramedMux};

    /// Test single-threaded executor.
    pub type TestSTExecutor = STExecutor<MemoryDuplex>;

    /// Creates a pair of single-threaded executors with memory I/O channels.
    pub fn test_st_executor(io_buffer: usize) -> (TestSTExecutor, TestSTExecutor) {
        let (io_0, io_1) = duplex(io_buffer);

        (STExecutor::new(io_0), STExecutor::new(io_1))
    }

    /// Test multi-threaded executor.
    pub type TestMTExecutor = MTExecutor<TestFramedMux, MemoryDuplex>;

    /// Creates a pair of multi-threaded executors with multiplexed I/O
    /// channels.
    ///
    /// # Arguments
    ///
    /// * `io_buffer` - The size of the I/O buffer (channel capacity).
    pub fn test_mt_executor(
        io_buffer: usize,
        config: MTConfig,
    ) -> (TestMTExecutor, TestMTExecutor) {
        let (mux_0, mux_1) = test_framed_mux(io_buffer);

        let exec_0 = MTExecutor::new(mux_0, config.clone());
        let exec_1 = MTExecutor::new(mux_1, config);

        (exec_0, exec_1)
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::*;
