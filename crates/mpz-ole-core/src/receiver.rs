//! Receiver implementation.

use mpz_fields::Field;

use crate::{
    core::{ReceiverAdjust, ReceiverShare, ShareAdjust},
    msg::{BatchAdjust, MaskedInputs},
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
    /// Generates new OLEs and stores them internally.
    ///
    /// # Arguments
    ///
    /// * `input` - The receiver's OLE input factors.
    /// * `random` - Uniformly random field elements.
    /// * `masked` - The correlations from the sender.
    pub fn preprocess(
        &mut self,
        input: Vec<F>,
        random: Vec<F>,
        masked: MaskedInputs<F>,
    ) -> Result<(), OLEError> {
        let masks = masked.try_into()?;
        let shares = ReceiverShare::new_vec::<N>(input, random, masks)?;

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
    pub fn consume(&mut self, count: usize) -> Option<Vec<ReceiverShare<F>>> {
        if count > self.cache.len() {
            return None;
        }

        let shares = self.cache.drain(..count).collect();
        Some(shares)
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
    /// * [`BatchAdjust`] which needs to be sent to the [`crate::OLESender`].
    pub fn adjust(&mut self, targets: Vec<F>) -> Option<(Vec<ReceiverAdjust<F>>, BatchAdjust<F>)> {
        let shares = self.consume(targets.len())?;
        let (sender_adjusted, adjustments) = shares
            .into_iter()
            .zip(targets)
            .map(|(s, t)| {
                let (share, adjust) = s.adjust(t);
                (share, adjust.0)
            })
            .unzip();

        let adjustments = BatchAdjust { adjustments };

        Some((sender_adjusted, adjustments))
    }

    /// Completes the adjustment and returns the new shares.
    ///
    /// # Arguments
    ///
    /// * `receiver_adjust` - The receiver's intermediate shares from [`OLEReceiver::adjust`].
    /// * `batch_adjust` - The sender's adjustments.
    ///
    /// # Returns
    ///
    /// * A vector of [`ReceiverShare`]s containing the new OLE outputs for the receiver.
    pub fn finish_adjust(
        &self,
        receiver_adjust: Vec<ReceiverAdjust<F>>,
        batch_adjust: BatchAdjust<F>,
    ) -> Result<Vec<ReceiverShare<F>>, OLEError> {
        let adjustments = batch_adjust.adjustments;

        if receiver_adjust.len() != adjustments.len() {
            return Err(OLEError::UnequalAdjustments(
                receiver_adjust.len(),
                adjustments.len(),
            ));
        }
        let shares = receiver_adjust
            .into_iter()
            .zip(adjustments.into_iter())
            .map(|(s, a)| s.finish(ShareAdjust(a)))
            .collect();

        Ok(shares)
    }
}
