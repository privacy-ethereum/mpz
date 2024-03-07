//! Common functionality for `mpz`.
//!
//! This crate provides various common functionalities needed for modeling protocol execution, I/O,
//! and multi-threading.
//!
//! This crate does not provide any cryptographic primitives, see `mpz-core` for that.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

mod context;
pub mod executor;
mod id;
#[cfg(feature = "sync")]
pub mod sync;

pub use context::Context;
pub use id::ThreadId;

// Re-export scoped-futures for use with the callback-like API in `Context`.
pub use scoped_futures;
