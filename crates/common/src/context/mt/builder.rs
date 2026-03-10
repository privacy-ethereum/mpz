use std::sync::{Arc, Mutex};

use crate::{
    ThreadId,
    context::{
        MtConfig, ThreadBuilder,
        mt::{Multithread, pool::SharedPool},
    },
    mux::Mux,
};

/// Builder for [`Multithread`].
#[derive(Default)]
pub struct MultithreadBuilder {
    /// Thread pool.
    pool: Option<SharedPool>,
    /// Multiplexer.
    mux: Option<Box<dyn Mux + Send>>,
}

impl MultithreadBuilder {
    /// Builds a new multi-threaded context.
    ///
    /// Both a [`SharedPool`] and a multiplexer must be set before calling
    /// this method.
    pub fn build(self) -> Result<Multithread, MultithreadBuilderError> {
        let pool = self
            .pool
            .ok_or(MultithreadBuilderError(ErrorRepr::MissingField("pool")))?;
        let mux = self
            .mux
            .ok_or(MultithreadBuilderError(ErrorRepr::MissingField("mux")))?;

        let concurrency = pool.num_threads();
        let senders = pool.senders().clone();

        let builder = ThreadBuilder { mux };

        Ok(Multithread {
            current_id: ThreadId::default(),
            config: Arc::new(MtConfig { concurrency }),
            builder: Arc::new(Mutex::new(builder)),
            senders,
            // Keep pool alive — dropping it shuts down workers.
            _pool: pool,
        })
    }

    /// Sets the thread pool.
    pub fn pool(mut self, pool: SharedPool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Sets the multiplexer.
    pub fn mux<M: Into<Box<dyn Mux + Send>>>(mut self, mux: M) -> Self {
        self.mux = Some(mux.into());
        self
    }
}

/// Error for [`MultithreadBuilder`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct MultithreadBuilderError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}
