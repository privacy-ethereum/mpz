//! Receiver shares for Oblivious Linear Function Evaluation (OLE).

use crate::{
    core::{MaskedCorrelation, ShareAdjust},
    OLEError,
};
use hybrid_array::Array;
use itybity::ToBits;
use mpz_fields::Field;

/// Receiver share for OLE.
#[derive(Debug)]
pub struct ReceiverShare<F> {
    input: F,
    output: F,
}

impl<F: Field> ReceiverShare<F> {
    /// Creates a new [`ReceiverShare`].
    ///
    /// # Arguments
    ///
    /// * `input` - The receiver's input share.
    /// * `random` - Uniformly random field elements.
    /// * `masked` - The correlation from the sender.
    ///
    /// # Returns
    ///
    /// * The receiver's share.
    pub(crate) fn new(
        input: F,
        random: impl Into<Array<F, F::BitSize>>,
        masked: MaskedCorrelation<F>,
    ) -> Self {
        let random = random.into();

        let delta_i = input.iter_lsb0();
        let ui = masked.0.iter();
        let t_delta_i = random.iter();

        let output = delta_i.zip(ui).zip(t_delta_i).enumerate().fold(
            F::zero(),
            |acc, (i, ((delta, &u), &t))| {
                let delta = if delta { F::one() } else { F::zero() };
                acc + F::two_pow(i as u32) * (delta * u + t)
            },
        );

        Self { input, output }
    }

    /// Generates a vector of new [`ReceiverShare`]s.
    ///
    /// # Arguments
    ///
    /// * `input` - The receiver's input share.
    /// * `random` - Uniformly random field elements.
    /// * `masked` - The correlations from the sender.
    ///
    /// # Returns
    ///
    /// * A vector of [`ReceiverShare`]s containing the OLE outputs for the receiver.
    pub fn new_vec(
        input: Vec<F>,
        random: Vec<F>,
        masked: Vec<MaskedCorrelation<F>>,
    ) -> Result<Vec<ReceiverShare<F>>, OLEError> {
        if input.len() * F::BIT_SIZE != random.len() {
            return Err(OLEError::ExpectedMultipleOf(
                input.len() * F::BIT_SIZE,
                random.len(),
            ));
        }

        if input.len() != masked.len() {
            return Err(OLEError::WrongNumberOfMasks(masked.len(), input.len()));
        }

        let shares: Vec<ReceiverShare<F>> = input
            .iter()
            .zip(random.chunks_exact(F::BIT_SIZE))
            .zip(masked)
            .map(|((&f, chunk), m)| {
                ReceiverShare::new(
                    f,
                    Array::<F, F::BitSize>::try_from(chunk)
                        .expect("Slice should have length of bit size of field element"),
                    m,
                )
            })
            .collect();

        Ok(shares)
    }

    /// Returns the receiver's output share.
    pub fn inner(self) -> F {
        self.output
    }

    /// Adjusts a preprocessed share.
    ///
    /// This is an implementation of <https://crypto.stackexchange.com/questions/100634/converting-a-random-ole-oblivious-linear-function-evaluation-to-an-ole>.
    ///
    /// # Arguments
    ///
    ///  * `target` - The new target input of the OLE.
    ///
    /// # Returns
    ///
    /// * The intermediate receiver share, which needs the sender's adjustment.
    /// * The receiver adjustment which needs to be sent to the sender.
    pub(crate) fn adjust(self, target: F) -> (ReceiverAdjust<F>, ShareAdjust<F>) {
        (
            ReceiverAdjust {
                old_output: self.output,
                new_input: target,
            },
            ShareAdjust(self.input + target),
        )
    }
}

/// Intermediate type for share adjustment of the receiver.
#[derive(Debug)]
pub struct ReceiverAdjust<F> {
    old_output: F,
    new_input: F,
}

impl<F: Field> ReceiverAdjust<F> {
    /// Finishes the adjustment and returns the adjusted receiver's share.
    pub(crate) fn finish(self, adjust: ShareAdjust<F>) -> ReceiverShare<F> {
        ReceiverShare {
            input: self.new_input,
            output: self.old_output + self.new_input * adjust.0,
        }
    }
}
