//! Implementations of Oblivious Linear Function Evaluation (OLE).
//!
//! Core logic of the protocol without I/O.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

pub mod ideal;

mod core;
mod receiver;
mod sender;

pub use receiver::OLEReceiver;
pub use sender::OLESender;
