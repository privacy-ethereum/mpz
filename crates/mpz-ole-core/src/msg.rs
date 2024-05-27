//! Message types for OLE.

use crate::{core::MaskedCorrelation, OLEError, TransferId};
use mpz_fields::Field;
use serde::{Deserialize, Serialize};

/// Message type for sending a vector of [`MaskedCorrelation`]s to the receiver.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize)]
pub struct MaskedCorrelations<F> {
    pub masks: Vec<F>,
}

impl<F: Field> From<Vec<MaskedCorrelation<F>>> for MaskedCorrelations<F> {
    fn from(value: Vec<MaskedCorrelation<F>>) -> Self {
        let masks = value.into_iter().flat_map(|mask| mask.0).collect();
        Self { masks }
    }
}

impl<F: Field> TryFrom<MaskedCorrelations<F>> for Vec<MaskedCorrelation<F>> {
    type Error = OLEError;

    fn try_from(value: MaskedCorrelations<F>) -> Result<Self, Self::Error> {
        let masks = value
            .masks
            .chunks(F::BIT_SIZE)
            .map(|chunk| {
                chunk
                    .try_into()
                    .map(MaskedCorrelation)
                    .map_err(|_| OLEError::MultipleOf(chunk.len(), F::BIT_SIZE))
            })
            .collect();
        masks
    }
}

/// Message type for sending a vector of [`crate::core::ShareAdjust`] to the other party.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchAdjust<F> {
    pub id: TransferId,
    pub adjustments: Vec<F>,
}
