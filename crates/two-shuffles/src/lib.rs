//! ZK data structures from "Two Shuffles Make a RAM" (Yang/Heath, 2023).
//!
//! Three protocols, layered:
//!
//! - [`ro_kvs`] — read-only key-value store (Section 4.1).
//! - [`set`] — set membership queries (Section 4.2; the same shape as RO-KVS
//!   minus the value column).
//! - [`ram`] — read/write RAM (Section 4.3).

#![deny(missing_docs)]

pub(crate) mod gf2n;

pub mod ram;
pub mod ro_kvs;
pub mod set;
pub mod strategy;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub mod wire;

pub use wire::{Bundle, ProverWire, VerifierWire};
