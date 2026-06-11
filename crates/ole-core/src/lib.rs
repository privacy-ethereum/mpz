//! Oblivious linear evaluation core library.
//!
//! This library provides the core functionality for oblivious linear evaluation
//! (OLE). OLE is a 2-party functionality defined as follows:
//!
//! - The sender defines a linear function `y = ab + x` and sends `a` and `x` to
//!   the functionality.
//! - The receiver sends their input `b` to the functionality.
//! - The functionality computes `y = ab + x` and returns `y` to the receiver.
//!
//! It's often easier to frame OLE as producing an additive sharing of a
//! product, where the sender knows `(a, x)` and the receiver knows `(b, y)`
//! such that `ab = x + y`. This representation is used in [`OLEShare`].
//!
//! # Constructions
//!
//! The crate root holds the shared functionality ([`OLEShare`], [`OLEId`], the
//! [`ROLESender`]/[`ROLEReceiver`] traits, [`Adjust`], the ideal functionality,
//! and test utilities). Each concrete construction lives in its own module:
//!
//! - [`gilboa`] — semi-honest OLE from Gilboa's OT-based multiplication.
//! - [`dhim`] — maliciously-secure, subquadratic-communication OLE.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

mod adjust;
pub mod dhim;
pub mod gilboa;
#[cfg(any(test, feature = "test-utils"))]
pub mod ideal;
mod role;
#[cfg(any(test, feature = "test-utils"))]
pub mod test;

pub use adjust::{Adjust, Offset};
pub use role::{ROLEReceiver, ROLEReceiverOutput, ROLESender, ROLESenderOutput};

use mpz_fields::Field;
use serde::{Deserialize, Serialize};

/// An OLE identifier.
///
/// Multiple OLEs may be batched together under the same ID.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct OLEId(u64);

impl std::fmt::Display for OLEId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OleId({})", self.0)
    }
}

impl OLEId {
    /// Returns the current ID, incrementing `self` in-place.
    pub(crate) fn next(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }
}

/// Share of an OLE.
#[derive(Debug, Clone, Copy)]
pub struct OLEShare<F> {
    /// Additive share.
    pub add: F,
    /// Multiplicative share.
    pub mul: F,
}

impl<F> OLEShare<F>
where
    F: Field,
{
    /// Adjusts the multiplicative share to the target.
    pub fn adjust(self, target: F) -> Adjust<F> {
        Adjust::new(target, self)
    }
}
