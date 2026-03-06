use std::sync::{Arc, Mutex};

use crate::{
    ThreadId,
    context::{
        CustomSpawn, MtConfig, SpawnError, ThreadBuilder,
        mt::{
            Multithread,
            pool::SharedPool,
            spawn::{Spawn, StdSpawn},
        },
    },
    mux::Mux,
};

/// Builder for [`Multithread`].
pub struct MultithreadBuilder<S = StdSpawn> {
    /// Number of worker threads in the pool.
    concurrency: usize,
    /// Closure invoked to spawn a new thread.
    spawn_handler: S,
    /// Multiplexer.
    mux: Option<Box<dyn Mux + Send>>,
}

impl Default for MultithreadBuilder {
    fn default() -> Self {
        Self {
            concurrency: 8,
            spawn_handler: StdSpawn,
            mux: None,
        }
    }
}

impl<S> MultithreadBuilder<S>
where
    S: Spawn,
{
    /// Builds a new multi-threaded context.
    ///
    /// This eagerly spawns the thread pool with `concurrency` worker threads.
    pub fn build(mut self) -> Result<Multithread, MultithreadBuilderError> {
        let mux = self
            .mux
            .ok_or(MultithreadBuilderError(ErrorRepr::MissingField("mux")))?;

        // Create the shared thread pool eagerly.
        let pool = SharedPool::new(self.concurrency, &mut self.spawn_handler)
            .map_err(|e| MultithreadBuilderError(ErrorRepr::Spawn(e)))?;

        let senders = pool.senders().clone();

        let builder = ThreadBuilder { mux };

        Ok(Multithread {
            current_id: ThreadId::default(),
            config: Arc::new(MtConfig {
                concurrency: self.concurrency,
            }),
            builder: Arc::new(Mutex::new(builder)),
            senders,
            // Keep pool alive — dropping it shuts down workers.
            _pool: pool,
        })
    }
}

impl<S> MultithreadBuilder<S> {
    /// Sets a custom function for spawning threads.
    pub fn spawn_handler<F>(self, spawn: F) -> MultithreadBuilder<CustomSpawn<F>>
    where
        F: FnMut(Box<dyn FnOnce() + Send>) -> Result<(), SpawnError> + Send + 'static,
    {
        MultithreadBuilder {
            spawn_handler: CustomSpawn(spawn),
            concurrency: self.concurrency,
            mux: self.mux,
        }
    }

    /// Sets the multiplexer.
    pub fn mux<M: Into<Box<dyn Mux + Send>>>(mut self, mux: M) -> Self {
        self.mux = Some(mux.into());
        self
    }

    /// Sets the number of worker threads in the pool.
    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
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
    #[error("failed to spawn thread pool: {0}")]
    Spawn(SpawnError),
}
