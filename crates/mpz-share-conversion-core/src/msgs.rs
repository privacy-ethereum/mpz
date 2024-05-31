//! Message types used in share conversion.

use crate::a2m::A2MMasks;
use serde::{Deserialize, Serialize};

/// Message type for sending [`A2MMasks`] to the receiver.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Masks<F> {
    pub masks: Vec<F>,
}

impl<F> From<A2MMasks<F>> for Masks<F> {
    fn from(value: A2MMasks<F>) -> Self {
        Self { masks: value.0 }
    }
}

impl<F> From<Masks<F>> for A2MMasks<F> {
    fn from(value: Masks<F>) -> Self {
        Self(value.masks)
    }
}
