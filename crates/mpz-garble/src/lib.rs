//! Garbled circuit VM implementations.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

pub(crate) mod evaluator;
pub(crate) mod generator;
pub mod protocol;
pub(crate) mod store;
