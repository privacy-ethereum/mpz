/// A runtime fault that aborts execution of a Wasm program.
///
/// A trap corresponds to a condition the Wasm specification defines as
/// unrecoverable, such as an out-of-bounds memory access or an integer divide
/// by zero. Unlike an [`Error`](crate::Error), a trap is a defined outcome of
/// executing a well-formed program rather than a misuse of the VM or an
/// unimplemented feature; the thread surfaces it as
/// [`StepResult::Trapped`](crate::StepResult::Trapped), not as an error.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Trap {
    /// An `unreachable` instruction was executed.
    #[error("unreachable instruction executed")]
    Unreachable,

    /// An integer division or remainder with a zero divisor was attempted.
    #[error("integer divide by zero")]
    DivideByZero,

    /// An integer operation produced a result outside the range of its type.
    #[error("integer overflow")]
    IntegerOverflow,

    /// A memory access fell outside the bounds of the linear memory.
    #[error("out of bounds memory access")]
    MemoryOutOfBounds,

    /// An indirect call referenced an undefined table element.
    #[error("undefined element")]
    UndefinedElement,

    /// An indirect call targeted a function whose signature did not match the
    /// expected type.
    #[error("indirect call type mismatch")]
    IndirectCallTypeMismatch,

    /// The call stack exceeded its maximum depth.
    #[error("call stack exhausted")]
    CallStackExhausted,

    /// The program terminated via an explicit exit with the given status code.
    #[error("process exit with code {0}")]
    Exit(i32),
}

/// A [`Result`] whose error case is a [`Trap`].
pub type MaybeTrap<T> = Result<T, Trap>;
