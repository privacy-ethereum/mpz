//! Receiver shares for Oblivious Linear Function Evaluation (OLE).

use super::{Check, MaskedInput, ShareAdjust};
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
    /// * `input` - The receiver's input share. This is his OT choice bits as a field element.
    /// * `ot_message_choices` - The receiver's OT message choices as field elements.
    /// * `masked` - The correlation masking the sender's input.
    ///
    /// # Returns
    ///
    /// * The receiver's share.
    pub(crate) fn new<const N: usize>(
        input: F,
        ot_message_choices: [F; N],
        masked: MaskedInput<N, F>,
    ) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        let delta_i = input.iter_lsb0();
        let ui = masked.0.iter();
        let t_delta_i = ot_message_choices.iter();

        let output = delta_i.zip(ui).zip(t_delta_i).enumerate().fold(
            F::zero(),
            |acc, (i, ((delta, &u), &t))| {
                let delta = if delta { F::one() } else { F::zero() };
                acc + F::two_pow(i as u32) * (delta * u + t)
            },
        );

        Self { input, output }
    }

    /// Returns the receiver's output share.
    pub fn inner(self) -> F {
        self.output
    }

    /// Adjust a preprocessed share.
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
