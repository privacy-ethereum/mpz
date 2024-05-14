//! Receiver implementation.

use mpz_fields::Field;

use crate::{
    core::{MaskedInput, ReceiverAdjust, ReceiverShare, ShareAdjust},
    OLEError,
};

/// A receiver for batched OLE.
#[derive(Debug)]
pub struct OLEReceiver<const N: usize, F> {
    cache: Vec<ReceiverShare<F>>,
}

impl<const N: usize, F: Field> Default for OLEReceiver<N, F> {
    fn default() -> Self {
        OLEReceiver { cache: vec![] }
    }
}

impl<const N: usize, F: Field> OLEReceiver<N, F> {
    /// Generates new OLEs.
    ///
    /// OLEs are not stored and directly returned.
    ///
    /// # Arguments
    ///
    /// * `input` - The receiver's OLE input factors.
    /// * `ot_message_choices` - The OT messages chosen by the receiver.
    /// * `masked` - The correlations from the sender.
    ///
    /// # Returns
    ///
    /// * A vector of [`ReceiverShare`]s containing the OLE outputs for the receiver.
    pub fn generate(
        &self,
        input: Vec<F>,
        ot_message_choices: Vec<F>,
        masked: Vec<MaskedInput<N, F>>,
    ) -> Result<Vec<ReceiverShare<F>>, OLEError> {
        if input.len() * F::BIT_SIZE as usize != ot_message_choices.len() {
            return Err(OLEError::ExpectedMultipleOf(
                input.len() * F::BIT_SIZE as usize,
                ot_message_choices.len(),
            ));
        }

        if input.len() != masked.len() {
            return Err(OLEError::WrongNumerOfMasks(masked.len(), input.len()));
        }

        let shares: Vec<ReceiverShare<F>> = input
            .iter()
            .zip(ot_message_choices.chunks_exact(F::BIT_SIZE as usize))
            .zip(masked)
            .map(|((&f, chunk), m)| {
                ReceiverShare::new::<N>(
                    f,
                    chunk
                        .try_into()
                        .expect("Slice should have length of bit size of field element"),
                    m,
                )
            })
            .collect();

        Ok(shares)
    }

    /// Generates new OLEs and stores them internally.
    ///
    /// This method is similar to [`OLEReceiver::generate`], except that [`ReceiverShare`]s are stored
    /// for later adjustment.
    ///
    /// # Arguments
    ///
    /// * `input` - The receiver's OLE input factors.
    /// * `ot_message_choices` - The OT messages chosen by the receiver.
    /// * `masked` - The correlations from the sender.
    pub fn preprocess(
        &mut self,
        input: Vec<F>,
        ot_message_choices: Vec<F>,
        masked: Vec<MaskedInput<N, F>>,
    ) -> Result<(), OLEError> {
        let shares = self.generate(input, ot_message_choices, masked)?;
        self.cache.extend(shares);

        Ok(())
    }

    /// Returns OLEs from internal cache.
    ///
    /// For consumption of OLEs which have been stored by [`OLEReceiver::preprocess`].
    ///
    /// # Arguments
    ///
    /// * `count` - The number of shares to return.
    ///
    /// # Returns
    ///
    /// * A vector of [`ReceiverShare`]s containing the OLE outputs for the receiver.
    pub fn consume(&mut self, count: usize) -> Result<Vec<ReceiverShare<F>>, OLEError> {
        if count > self.cache.len() {
            return Err(OLEError::InsufficientOLEs(count, self.cache.len()));
        }

        let shares = self.cache.drain(..count).collect();
        Ok(shares)
    }

    /// Adjusts OLEs in the internal cache.
    ///
    /// # Arguments
    ///
    /// * `targets` - The new OLE receiver inputs.
    ///
    /// # Returns
    ///
    /// * A vector of [`ReceiverAdjust`] which needs to be converted by [`OLEReceiver::finish_adjust`].
    /// * A vector of [`ShareAdjust`] which needs to be sent to the [`super::OLESender`].
    pub fn adjust(
        &mut self,
        targets: Vec<F>,
    ) -> Result<(Vec<ReceiverAdjust<F>>, Vec<ShareAdjust<F>>), OLEError> {
        let shares = self.consume(targets.len())?;
        let (sender_adjusted, adjustments) = shares
            .into_iter()
            .zip(targets)
            .map(|(s, t)| s.adjust(t))
            .unzip();

        Ok((sender_adjusted, adjustments))
    }

    /// Completes the adjustment and returns the new shares.
    ///
    /// # Arguments
    ///
    /// * `receiver_adjust` - The receiver's intermediate shares from [`OLEReceiver::adjust`].
    /// * `adjustments` - The sender's adjustments.
    ///
    /// # Returns
    ///
    /// * A vector of [`ReceiverShare`]s containing the new OLE outputs for the receiver.
    pub fn finish_adjust(
        &self,
        receiver_adjust: Vec<ReceiverAdjust<F>>,
        adjustments: Vec<ShareAdjust<F>>,
    ) -> Result<Vec<ReceiverShare<F>>, OLEError> {
        if receiver_adjust.len() != adjustments.len() {
            return Err(OLEError::UnequalAdjustments(
                receiver_adjust.len(),
                adjustments.len(),
            ));
        }
        let shares = receiver_adjust
            .into_iter()
            .zip(adjustments.into_iter())
            .map(|(s, a)| s.finish(a))
            .collect();

        Ok(shares)
    }
}
