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

#[doc(hidden)]
pub trait Spawn: Send + 'static {
    /// Spawns a new thread.
    fn spawn(&mut self, f: Box<dyn FnOnce() + Send>) -> Result<(), SpawnError>;
}

#[doc(hidden)]
pub struct StdSpawn;

impl Spawn for StdSpawn {
    fn spawn(&mut self, f: Box<dyn FnOnce() + Send>) -> Result<(), SpawnError> {
        std::thread::Builder::new()
            .spawn(f)
            .map(|_| ())
            .map_err(SpawnError::new)
    }
}

#[doc(hidden)]
pub struct CustomSpawn<F>(pub F);

impl<F> Spawn for CustomSpawn<F>
where
    F: FnMut(Box<dyn FnOnce() + Send>) -> Result<(), SpawnError> + Send + 'static,
{
    fn spawn(&mut self, f: Box<dyn FnOnce() + Send>) -> Result<(), SpawnError> {
        (self.0)(f)
    }
}
