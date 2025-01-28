use std::sync::{Arc, Mutex};

use uid_mux::UidMux;

use crate::{
    context::{
        mt::{
            spawn::{Spawn, StdSpawn},
            Multithread,
        },
        CustomSpawn, MtConfig, SpawnError, ThreadBuilder,
    },
    mux::Mux,
    ThreadId,
};

/// Builder for [`Multithread`].
pub struct MultithreadBuilder<S = StdSpawn> {
    /// Maximum concurrency level per thread.
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
    pub fn build(self) -> Result<Multithread, MultithreadBuilderError> {
        let mux = self
            .mux
            .ok_or_else(|| MultithreadBuilderError(ErrorRepr::MissingField("mux")))?;

        let builder = ThreadBuilder {
            spawn: Box::new(self.spawn_handler),
            mux,
        };

        Ok(Multithread {
            current_id: ThreadId::default(),
            config: Arc::new(MtConfig {
                concurrency: self.concurrency,
            }),
            builder: Arc::new(Mutex::new(builder)),
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
    pub fn mux<M>(mut self, mux: M) -> Self
    where
        M: UidMux<ThreadId> + Clone + Send + Sync + 'static,
        <M as UidMux<ThreadId>>::Error: std::error::Error + Send + Sync + 'static,
    {
        self.mux = Some(Box::new(mux));
        self
    }

    pub(crate) fn mux_internal(mut self, mux: Box<dyn Mux + Send>) -> Self {
        self.mux = Some(mux);
        self
    }

    /// Sets the maximum concurrency level per thread.
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
}
