//! Sender shares for Oblivious Linear Function Evaluation (OLE).

use crate::{
    core::{MaskedInput, ShareAdjust},
    OLEError,
};
use hybrid_array::{Array, ArraySize};
use mpz_fields::Field;

/// Sender share for OLE.
#[derive(Debug)]
pub struct SenderShare<F> {
    input: F,
    output: F,
}

impl<F: Field> SenderShare<F>
where
    <F as Field>::BitSizeType: ArraySize,
{
    /// Creates a new [`SenderShare`].
    ///
    /// # Arguments
    ///
    /// * `input` - The sender's input share.
    /// * `random` - Uniformly random field elements for the correlation.
    ///
    /// # Returns
    ///
    /// * The sender's share.
    /// * The correlation which will be sent to the receiver.
    pub(crate) fn new(
        input: F,
        random: impl Into<Array<[F; 2], F::BitSizeType>>,
    ) -> (Self, MaskedInput<F>) {
        let random = random.into();

        let output = random
            .as_slice()
            .iter()
            .enumerate()
            .fold(F::zero(), |acc, (i, &[zero, _])| {
                acc + F::two_pow(i as u32) * zero
            });
        let share = Self { input, output };

        let mut ui: Array<F, F::BitSizeType> = Array::from_fn(|_| F::zero());
        ui.as_mut_slice()
            .iter_mut()
            .zip(random)
            .for_each(|(u, [zero, one])| *u = zero + -one + input);
        let masked = MaskedInput(ui);

        (share, masked)
    }

    /// Generates a vector of new [`SenderShare`]s.
    ///
    /// # Arguments
    ///
    /// * `input` - The sender's input share.
    /// * `random` - Uniformly random field elements for the correlation.
    ///
    /// # Returns
    ///
    /// * A vector of sender shares.
    /// * A vector of correlations, which are to be sent to the receiver.
    #[allow(clippy::type_complexity)]
    pub fn new_vec(
        input: Vec<F>,
        random: Vec<[F; 2]>,
    ) -> Result<(Vec<SenderShare<F>>, Vec<MaskedInput<F>>), OLEError> {
        if input.len() * F::BIT_SIZE as usize != random.len() {
            return Err(OLEError::ExpectedMultipleOf(
                input.len() * F::BIT_SIZE as usize,
                random.len(),
            ));
        }

        let (shares, masked): (Vec<SenderShare<F>>, Vec<MaskedInput<F>>) = input
            .iter()
            .zip(random.chunks_exact(F::BIT_SIZE as usize))
            .map(|(&f, chunk)| {
                SenderShare::new(
                    f,
                    Array::<[F; 2], F::BitSizeType>::try_from(chunk)
                        .expect("Slice should have length of bit size of field element"),
                )
            })
            .unzip();

        Ok((shares, masked))
    }

    /// Returns the sender's output share.
    pub fn inner(self) -> F {
        self.output
    }

    /// Adjust a preprocessed share.
    ///
    /// This is an implementation of <https://crypto.stackexchange.com/questions/100634/converting-a-random-ole-oblivious-linear-function-evaluation-to-an-ole>.
    ///
    /// # Arguments
    ///
    ///  * `target` - The new target input for the OLE.
    ///
    /// # Returns
    ///
    /// * The intermediate sender share, which needs the receiver's adjustment.
    /// * The sender adjustment which needs to be sent to the receiver.
    pub(crate) fn adjust(self, target: F) -> (SenderAdjust<F>, ShareAdjust<F>) {
        (
            SenderAdjust {
                old_input: self.input,
                old_output: self.output,
                new_input: target,
            },
            ShareAdjust(self.input + target),
        )
    }
}

/// Intermediate type for share adjustment of the sender.
#[derive(Debug)]
pub struct SenderAdjust<F> {
    old_input: F,
    old_output: F,
    new_input: F,
}

impl<F: Field> SenderAdjust<F> {
    /// Finishes the adjustment and returns the adjusted sender's share.
    pub(crate) fn finish(self, adjust: ShareAdjust<F>) -> SenderShare<F> {
        SenderShare {
            input: self.new_input,
            output: self.old_output + self.old_input * adjust.0,
        }
    }
}
