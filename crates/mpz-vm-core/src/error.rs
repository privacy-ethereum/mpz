/// Vm error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct VmError(ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("vm error: {0}")]
enum ErrorRepr {
    #[error("memory error: {0}")]
    Memory(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("call error: {0}")]
    Call(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("view error: {0}")]
    View(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("execution error: {0}")]
    Execute(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl VmError {
    /// Creates a new memory error.
    pub fn memory<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Memory(err.into()))
    }

    /// Creates a new call error.
    pub fn call<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Call(err.into()))
    }

    /// Creates a new view error.
    pub fn view<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::View(err.into()))
    }

    /// Creates a new execution error.
    pub fn execute<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Execute(err.into()))
    }
}

impl From<std::io::Error> for VmError {
    fn from(value: std::io::Error) -> Self {
        Self(ErrorRepr::Execute(value.into()))
    }
}
