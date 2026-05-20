//! Low-level crate containing core functionalities for vector oblivious
//! linear evaluation protocols.
//!
//! Covers VOLE (`m = k + Δ·v`) and its polynomial generalization VOPE
//! (`y = Σᵢ cᵢ·Δⁱ`). A degree-1 VOPE coincides with a VOLE; higher
//! degrees are typically built from multiple VOLEs, so both primitives
//! live in this crate.
//!
//! This crate is not intended to be used directly. Instead, use the
//! higher-level APIs provided by the `mpz-vole` crate.
//!
//! # ⚠️ Warning ⚠️
//!
//! Some implementations make assumptions about invariants which may not be
//! checked if using these low-level APIs naively. Failing to uphold these
//! invariants may result in security vulnerabilities.
//!
//! USE AT YOUR OWN RISK.

use serde::{Deserialize, Serialize};

pub mod ideal;
pub mod rvole;
pub mod rvope;
pub mod test;
pub mod vole;

pub use rvole::{RVOLEReceiver, RVOLEReceiverOutput, RVOLESender, RVOLESenderOutput};
pub use rvope::{RVOPEReceiver, RVOPEReceiverOutput, RVOPESender, RVOPESenderOutput};
pub use vole::{
    DerandVOLEReceiver, DerandVOLEReceiverError, DerandVOLESender, DerandVOLESenderError,
    VOLEReceiver, VOLEReceiverOutput, VOLESender, VOLESenderOutput, VoleAdjustment,
};

/// A VOLE identifier.
///
/// Multiple correlations may be batched together under the same VOLE ID.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct VoleId(u64);

impl VoleId {
    /// Returns the current VOLE ID, incrementing `self` in-place.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }
}

impl std::fmt::Display for VoleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VoleId({})", self.0)
    }
}
