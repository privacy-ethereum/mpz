/// Error for [`Spawn`]
#[derive(Debug, thiserror::Error)]
#[error("spawn error: {source}")]
pub struct SpawnError {
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl SpawnError {
    /// Creates a new spawn error.
    pub fn new<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            source: source.into(),
        }
    }
}

/// Thread spawner.
pub trait Spawn {
    /// Spawns a new thread, executing the provided function.
    fn spawn<F>(&self, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce() + Send + 'static;
}

/// `std` thread spawner.
pub struct StdSpawn;

impl Spawn for StdSpawn {
    fn spawn<F>(&self, f: F) -> Result<(), SpawnError>
    where
        F: FnOnce() + Send + 'static,
    {
        std::thread::Builder::new()
            .spawn(f)
            .map(|_| ())
            .map_err(SpawnError::new)
    }
}
