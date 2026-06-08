use crate::trap::Trap;
use crate::value::ValueError;

/// The error type of `mpz-vm-core-new`.
///
/// `Error` describes conditions intrinsic to the interpreter and to module
/// instantiation: misuse of the step/resolve protocol, references to module
/// items that do not exist, constructs the interpreter does not yet implement,
/// resource limits, and internal invariant violations. It deliberately does
/// *not* judge whether an operation is "supported" by any particular
/// backend — that is the embedder's verdict, rendered from the directives and
/// blocks the thread surfaces, and expressed through the embedder's own
/// [`Vm::Error`](crate::Vm::Error).
///
/// A [`Trap`] is *not* an `Error`: the thread surfaces traps as
/// [`StepResult::Trapped`](crate::StepResult::Trapped). The [`Error::Trap`]
/// variant exists only for traps raised while *instantiating* a module (for
/// example a data segment that falls out of bounds), which happens before any
/// stepping.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// [`Thread::call`](crate::Thread::call) was invoked while a call was
    /// already in progress.
    #[error("thread is already running a call")]
    AlreadyRunning,

    /// [`Thread::step`](crate::Thread::step) was called before
    /// [`Thread::call`](crate::Thread::call) started a call.
    #[error("no call in progress; start one with `call` first")]
    NotStarted,

    /// [`Thread::step`](crate::Thread::step) was called after the call
    /// completed.
    #[error("the call has already completed")]
    Completed,

    /// [`Thread::step`](crate::Thread::step) was called while the thread is
    /// blocked on a pending condition.
    #[error("thread is blocked on a pending condition; resolve it first")]
    Blocked,

    /// A `resolve_*` method was called while the thread was not blocked.
    #[error("thread is not blocked on a pending condition")]
    NotBlocked,

    /// A `resolve_*` method did not match the kind of the pending condition.
    #[error("resolution does not match the pending condition")]
    UnexpectedResolution,

    /// A host call that returns a value was resolved without one.
    #[error("host call requires a return value")]
    MissingHostCallValue,

    /// A value could not be interpreted as the required type.
    #[error(transparent)]
    Value(#[from] ValueError),

    /// No function exists at the referenced index.
    #[error("undefined function: {0}")]
    UndefinedFunction(u32),

    /// The referenced function is not a local function.
    #[error("invalid function: {0}")]
    InvalidFunction(u32),

    /// No global variable exists at the referenced index.
    #[error("undefined global: {0}")]
    UndefinedGlobal(u32),

    /// The module does not define a linear memory.
    #[error("memory not defined")]
    MemoryNotDefined,

    /// The interpreter does not implement this IR construct or exceeds a
    /// resource limit. This is a gap in this implementation, not a statement
    /// about any embedder.
    #[error("unimplemented: {0}")]
    Unimplemented(&'static str),

    /// A trap raised while instantiating a module, before stepping begins.
    #[error("trap during instantiation: {0}")]
    Trap(Trap),

    /// An invariant of the VM was violated, indicating a bug.
    #[error("internal error: {0}")]
    Internal(String),
}
