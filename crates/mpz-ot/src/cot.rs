//! Correlated OT.

mod derandomize;

pub use derandomize::{
    DerandCOTReceiver, DerandCOTReceiverError, DerandCOTSender, DerandCOTSenderError,
};
pub use mpz_ot_core::cot::{COTReceiver, COTReceiverOutput, COTSender, COTSenderOutput};
