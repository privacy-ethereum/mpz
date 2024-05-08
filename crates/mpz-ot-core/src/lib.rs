//! Low-level crate containing core functionalities for oblivious transfer protocols.
//!
//! This crate is not intended to be used directly. Instead, use the higher-level APIs provided by
//! the `mpz-ot` crate.
//!
//! # ⚠️ Warning ⚠️
//!
//! Some implementations make assumptions about invariants which may not be checked if using these
//! low-level APIs naively. Failing to uphold these invariants may result in security vulnerabilities.
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

use serde::{Deserialize, Serialize};

pub mod chou_orlandi;
pub mod ferret;
pub mod ideal;
pub mod kos;
pub mod msgs;
#[cfg(test)]
pub(crate) mod test;

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
    /// Returns the current transfer ID, incrementing `self` in-place.
    pub(crate) fn next(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }
}

/// The output the sender receives from the COT functionality.
#[derive(Debug)]
pub struct COTSenderOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The `0-bit` messages.
    pub msgs: Vec<T>,
}

/// The output the receiver receives from the COT functionality.
#[derive(Debug)]
pub struct COTReceiverOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The chosen messages.
    pub msgs: Vec<T>,
}

/// The output the sender receives from the random COT functionality.
#[derive(Debug)]
pub struct RCOTSenderOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The msgs.
    pub msgs: Vec<T>,
}

/// The output the receiver receives from the random COT functionality.
#[derive(Debug)]
pub struct RCOTReceiverOutput<T, U> {
    /// The transfer id.
    pub id: TransferId,
    /// The choice bits.
    pub choices: Vec<T>,
    /// The chosen messages.
    pub msgs: Vec<U>,
}

/// The output the sender receives from the ROT functionality.
#[derive(Debug)]
pub struct ROTSenderOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The random messages.
    pub msgs: Vec<T>,
}

/// The output the receiver receives from the ROT functionality.
#[derive(Debug)]
pub struct ROTReceiverOutput<T, U> {
    /// The transfer id.
    pub id: TransferId,
    /// The choice bits.
    pub choices: Vec<T>,
    /// The chosen messages.
    pub msgs: Vec<U>,
}

/// The output the sender receives from the OT functionality.
#[derive(Debug)]
pub struct OTSenderOutput {
    /// The transfer id.
    pub id: TransferId,
}

/// The output the receiver receives from the OT functionality.
#[derive(Debug)]
pub struct OTReceiverOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The chosen messages.
    pub msgs: Vec<T>,
}

/// The output that sender receivers from the SPCOT functionality.
#[derive(Debug)]
pub struct SPCOTSenderOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The random blocks that sender receives from the SPCOT functionality.
    pub v: Vec<Vec<T>>,
}

/// The output that receiver receives from the SPCOT functionality.
#[derive(Debug)]
pub struct SPCOTReceiverOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The random blocks that receiver receives from the SPCOT functionality.
    pub w: Vec<Vec<T>>,
}

/// The output that sender receives from the MPCOT functionality.
#[derive(Debug)]
pub struct MPCOTSenderOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The random blocks that sender receives from the MPCOT functionality.
    pub s: Vec<T>,
}

/// The output that receiver receives from the MPCOT functionality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MPCOTReceiverOutput<T> {
    /// The transfer id.
    pub id: TransferId,
    /// The random blocks that receiver receives from the MPCOT functionality.
    pub r: Vec<T>,
}
