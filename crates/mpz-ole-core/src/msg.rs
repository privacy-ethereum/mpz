//! Message types for OLE.

use crate::{core::MaskedInput, OLEError, TransferId};
use mpz_fields::Field;
use serde::{Deserialize, Serialize};

/// Message type for sending a vector [`MaskedInput`]s to the receiver.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize)]
pub struct MaskedInputs<F> {
    pub masks: Vec<F>,
}

impl<F: Field> From<Vec<MaskedInput<F>>> for MaskedInputs<F> {
    fn from(value: Vec<MaskedInput<F>>) -> Self {
        let masks = value.into_iter().flat_map(|mask| mask.0).collect();
        Self { masks }
    }
}

impl<F: Field> TryFrom<MaskedInputs<F>> for Vec<MaskedInput<F>> {
    type Error = OLEError;

    fn try_from(value: MaskedInputs<F>) -> Result<Self, Self::Error> {
        let masks = value
            .masks
            .chunks(F::BIT_SIZE as usize)
            .map(|chunk| {
                chunk
                    .try_into()
                    .map(MaskedInput)
                    .map_err(|_| OLEError::MultipleOf(chunk.len(), F::BIT_SIZE as usize))
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
