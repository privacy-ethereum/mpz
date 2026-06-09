//! The pure profiler core, shared by the native CLI and the in-browser
//! (wasm) profiler.
//!
//! [`Tracer`] is a single-party tracing VM built directly on `mpz-vm-core`: it
//! runs a parsed [`Module`](mpz_vm_ir::Module) to completion while recording
//! every emitted directive and private control-flow transition. [`stats`]
//! aggregates a trace into the histograms and block/call tables the Cost
//! Explorer renders, and [`render`] serializes them to JSON.
//!
//! This crate is target-agnostic — it carries no I/O, async, or platform
//! dependencies — so it compiles unchanged for `wasm32-unknown-unknown`.

pub mod render;
pub mod stats;
pub mod tracer;

pub use tracer::{Outcome, TraceEvent, Tracer, TracerError};
