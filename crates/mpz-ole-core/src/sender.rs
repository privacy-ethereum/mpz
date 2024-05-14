//! Sender implementation.

use mpz_fields::Field;

use crate::{
    core::{MaskedInput, SenderAdjust, SenderShare, ShareAdjust},
    OLEError,
};

/// A sender for batched OLE.
#[derive(Debug)]
pub struct OLESender<const N: usize, F> {
    cache: Vec<SenderShare<F>>,
}

impl<const N: usize, F: Field> Default for OLESender<N, F> {
    fn default() -> Self {
        OLESender { cache: vec![] }
    }
}

impl<const N: usize, F: Field> OLESender<N, F> {
    /// Generates new OLEs.
    ///
    /// OLEs are not stored and directly returned.
    ///
    /// # Arguments
    ///
    /// * `input` - The sender's OLE input factors.
    /// * `ot_messages` - The OT messages used for generating correlations.
    ///
    /// # Returns
    ///
    /// * A vector of [`SenderShare`]s containing the OLE outputs for the sender.
    /// * A vector of [`MaskedInput`]s, which is to be sent to the receiver.
    pub fn generate(
        &self,
        input: Vec<F>,
        ot_messages: Vec<[F; 2]>,
    ) -> Result<(Vec<SenderShare<F>>, Vec<MaskedInput<N, F>>), OLEError> {
        if input.len() * F::BIT_SIZE as usize != ot_messages.len() {
            return Err(OLEError::ExpectedMultipleOf(
                input.len() * F::BIT_SIZE as usize,
                ot_messages.len(),
            ));
        }

        let (shares, masked): (Vec<SenderShare<F>>, Vec<MaskedInput<N, F>>) = input
            .iter()
            .zip(ot_messages.chunks_exact(F::BIT_SIZE as usize))
            .map(|(&f, chunk)| {
                SenderShare::new::<N>(
                    f,
                    chunk
                        .try_into()
                        .expect("Slice should have length of bit size of field element"),
                )
            })
            .unzip();

        Ok((shares, masked))
    }

    /// Generates new OLEs and stores them internally.
    ///
    /// This method is similar to [`OLESender::generate`], except that [`SenderShare`]s are stored
    /// for later adjustment.
    ///
    /// # Arguments
    ///
    /// * `input` - The sender's OLE input factors.
    /// * `ot_messages` - The OT messages used for generating correlations.
    ///
    /// # Returns
    ///
    /// * A vector of [`MaskedInput`]s, which is to be sent to the [`super::OLEReceiver`].
    pub fn preprocess(
        &mut self,
        input: Vec<F>,
        ot_messages: Vec<[F; 2]>,
    ) -> Result<Vec<MaskedInput<N, F>>, OLEError> {
        let (shares, masked) = self.generate(input, ot_messages)?;
        self.cache.extend(shares);

        Ok(masked)
    }

    /// Returns OLEs from internal cache.
    ///
    /// For consumption of OLEs which have been stored by [`OLESender::preprocess`].
    ///
    /// # Arguments
    ///
    /// * `count` - The number of shares to return.
    ///
    /// # Returns
    ///
    /// * A vector of [`SenderShare`]s containing the OLE output for the sender.
    pub fn consume(&mut self, count: usize) -> Result<Vec<SenderShare<F>>, OLEError> {
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
    /// * `targets` - The new OLE sender inputs.
    ///
    /// # Returns
    ///
    /// * A vector of [`SenderAdjust`]s which needs to be converted by [`OLESender::finish_adjust`].
    /// * A vector of [`ShareAdjust`]s which needs to be sent to the [`super::OLEReceiver`].
    pub fn adjust(
        &mut self,
        targets: Vec<F>,
    ) -> Result<(Vec<SenderAdjust<F>>, Vec<ShareAdjust<F>>), OLEError> {
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
    /// * `sender_adjust` - The sender's intermediate shares from [`OLESender::adjust`].
    /// * `adjustments` - The receiver's adjustments.
    ///
    /// # Returns
    ///
    /// * A vector of [`SenderShare`]s containing the new OLE outputs for the sender.
    pub fn finish_adjust(
        &self,
        sender_adjust: Vec<SenderAdjust<F>>,
        adjustments: Vec<ShareAdjust<F>>,
    ) -> Result<Vec<SenderShare<F>>, OLEError> {
        if sender_adjust.len() != adjustments.len() {
            return Err(OLEError::UnequalAdjustments(
                sender_adjust.len(),
                adjustments.len(),
            ));
        }
        let shares = sender_adjust
            .into_iter()
            .zip(adjustments.into_iter())
            .map(|(s, a)| s.finish(a))
            .collect();

        Ok(shares)
    }
}
