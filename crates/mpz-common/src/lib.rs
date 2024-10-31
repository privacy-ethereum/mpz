//! Common functionality for `mpz`.
//!
//! This crate provides various common functionalities needed for modeling
//! protocol execution, I/O, and multi-threading.
//!
//! This crate does not provide any cryptographic primitives, see `mpz-core` for
//! that.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

mod context;
#[cfg(any(test, feature = "cpu"))]
pub mod cpu;
#[cfg(any(test, feature = "executor"))]
pub mod executor;
#[cfg(any(test, feature = "future"))]
pub mod future;
mod id;
#[cfg(any(test, feature = "ideal"))]
pub mod ideal;
#[cfg(feature = "sync")]
pub mod sync;

pub use context::{Context, ContextError};
pub use id::{Counter, ThreadId};

// Re-export scoped-futures for use with the callback-like API in `Context`.
pub use scoped_futures;

use async_trait::async_trait;

/// Allocates capacity from a functionality in the pre-processing model.
pub trait Allocate {
    /// Allocates `count` capacity.
    fn alloc(&mut self, count: usize);
}

/// A functionality in the pre-processing model.
#[async_trait]
pub trait Preprocess<Ctx>: Allocate {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Preprocesses the functionality.
    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error>;
}

/// A functionality that can be flushed.
#[async_trait]
pub trait Flush<Ctx> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns `true` if the functionality wants to be flushed.
    fn wants_flush(&self) -> bool;

    /// Flushes the functionality.
    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error>;
}

/// A convenience macro for creating a closure which returns a scoped future.
///
/// # Example
///
/// ```
/// # use mpz_common::scoped;
///
/// let closure = scoped!(|a: u8, b: u16| a as u16 + b);
/// let fut = closure(1, 2);
///
/// fn is_future<T: futures::Future<Output = u16>>(_: T) {}
///
/// is_future(fut);
/// ```
#[macro_export]
macro_rules! scoped {
    // Async move block.
    (| $($arg:ident $(: $typ:ty)?),* | async move $body:block) => {{
        #[allow(unused_imports)]
        use $crate::scoped_futures::ScopedFutureExt;
        | $($arg $( : $typ )?),* | async move $body.scope_boxed()
    }};
    // Async move block, move.
    (move | $($arg:ident $(: $typ:ty)?),* | async move $body:block) => {{
        #[allow(unused_imports)]
        use $crate::scoped_futures::ScopedFutureExt;
        move | $($arg $( : $typ )?),* | async move $body.scope_boxed()
    }};
    // No async block.
    (| $($arg:ident $(: $typ:ty)?),* | $body:expr) => {{
        #[allow(unused_imports)]
        use $crate::scoped_futures::ScopedFutureExt;
        | $($arg $( : $typ )?),* | async move { $body }.scope_boxed()
    }};
    // No async block, move.
    (move | $($arg:ident $(: $typ:ty)?),* | $body:expr) => {{
        #[allow(unused_imports)]
        use $crate::scoped_futures::ScopedFutureExt;
        move | $($arg $( : $typ )?),* | async move { $body }.scope_boxed()
    }};
}

#[cfg(test)]
mod tests {
    use futures::Future;

    #[test]
    fn test_scoped_macro() {
        fn assert_signature<T, Fut>(_: T)
        where
            T: Fn(u8, u16) -> Fut,
            Fut: Future<Output = u8>,
        {
        }

        assert_signature(scoped! {
            |a: u8, _b: u16| async move { a }
        });

        assert_signature(scoped! {
            move |a, _b| async move { a }
        });

        assert_signature(scoped! {
            |a, _b| a
        });

        assert_signature(scoped! {
            move |a: u8, _b| a
        });

        assert_signature(scoped! {
            |a: u8, _b| a
        });

        assert_signature(scoped! {
            |a, _b: u16| a
        });
    }
}
