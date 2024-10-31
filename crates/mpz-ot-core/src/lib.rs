//! Low-level crate containing core functionalities for oblivious transfer
//! protocols.
//!
//! This crate is not intended to be used directly. Instead, use the
//! higher-level APIs provided by the `mpz-ot` crate.
//!
//! # ⚠️ Warning ⚠️
//!
//! Some implementations make assumptions about invariants which may not be
//! checked if using these low-level APIs naively. Failing to uphold these
//! invariants may result in security vulnerabilities.
//!
//! USE AT YOUR OWN RISK.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

use mpz_core::bitvec::BitVec;
use serde::{Deserialize, Serialize};

pub mod chou_orlandi;
pub mod cot;
pub mod ideal;
pub mod kos;
pub mod ot;
pub mod rcot;
pub mod rot;
#[cfg(any(test, feature = "test-utils"))]
pub mod test;

/// An oblivious transfer identifier.
///
/// Multiple transfers may be batched together under the same transfer ID.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct TransferId(u64);

impl std::fmt::Display for TransferId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransferId({})", self.0)
    }
}

impl TransferId {
    pub(crate) fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the current transfer ID, incrementing `self` in-place.
    pub(crate) fn next(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }
}

/// A message sent by the receiver which a sender can use to perform
/// Beaver derandomization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Derandomize {
    /// Correction bits
    pub flip: BitVec,
}
