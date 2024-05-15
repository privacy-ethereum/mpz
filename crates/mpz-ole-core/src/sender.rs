//! Sender implementation.

use mpz_fields::Field;

use crate::{
    core::{SenderAdjust, SenderShare, ShareAdjust},
    msg::{BatchAdjust, MaskedInputs},
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
    /// Generates new OLEs and stores them internally.
    ///
    /// # Arguments
    ///
    /// * `input` - The sender's OLE input factors.
    /// * `random` - Uniformly random field elements for the correlation.
    ///
    /// # Returns
    ///
    /// * A vector of [`MaskedInput`]s, which is to be sent to the [`crate::OLEReceiver`].
    pub fn preprocess(
        &mut self,
        input: Vec<F>,
        random: Vec<[F; 2]>,
    ) -> Result<MaskedInputs<F>, OLEError> {
        let (shares, masked) = SenderShare::new_vec::<N>(input, random)?;
        self.cache.extend(shares);

        Ok(masked.into())
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
    pub fn consume(&mut self, count: usize) -> Option<Vec<SenderShare<F>>> {
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
    /// * `targets` - The new OLE sender inputs.
    ///
    /// # Returns
    ///
    /// * A vector of [`SenderAdjust`]s which needs to be converted by [`OLESender::finish_adjust`].
    /// * [`BatchAdjust`] which needs to be sent to the [`crate::OLEReceiver`].
    pub fn adjust(&mut self, targets: Vec<F>) -> Option<(Vec<SenderAdjust<F>>, BatchAdjust<F>)> {
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
    /// * `sender_adjust` - The sender's intermediate shares from [`OLESender::adjust`].
    /// * `batch_adjust` - The receiver's adjustments.
    ///
    /// # Returns
    ///
    /// * A vector of [`SenderShare`]s containing the new OLE outputs for the sender.
    pub fn finish_adjust(
        &self,
        sender_adjust: Vec<SenderAdjust<F>>,
        batch_adjust: BatchAdjust<F>,
    ) -> Result<Vec<SenderShare<F>>, OLEError> {
        let adjustments = batch_adjust.adjustments;

        if sender_adjust.len() != adjustments.len() {
            return Err(OLEError::UnequalAdjustments(
                sender_adjust.len(),
                adjustments.len(),
            ));
        }
        let shares = sender_adjust
            .into_iter()
            .zip(adjustments.into_iter())
            .map(|(s, a)| s.finish(ShareAdjust(a)))
            .collect();

        Ok(shares)
    }
}
