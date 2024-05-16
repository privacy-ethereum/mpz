//! Receiver implementation.

use mpz_fields::Field;

use crate::{
    core::{ReceiverAdjust, ReceiverShare, ShareAdjust},
    msg::{BatchAdjust, MaskedInputs},
    OLEError, TransferId,
};

/// A receiver for batched OLE.
#[derive(Debug)]
pub struct OLEReceiver<const N: usize, F> {
    id: TransferId,
    cache: Vec<ReceiverShare<F>>,
}

impl<const N: usize, F: Field> Default for OLEReceiver<N, F> {
    fn default() -> Self {
        OLEReceiver {
            id: TransferId::default(),
            cache: Vec::default(),
        }
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
    /// * [`BatchReceiverAdjust`] which needs to be converted by [`BatchReceiverAdjust::finish_adjust`].
    /// * [`BatchAdjust`] which needs to be sent to the [`crate::OLESender`].
    pub fn adjust(&mut self, targets: Vec<F>) -> Option<(BatchReceiverAdjust<F>, BatchAdjust<F>)> {
        let shares = self.consume(targets.len())?;
        let (receiver_adjust, adjustments) = shares
            .into_iter()
            .zip(targets)
            .map(|(s, t)| {
                let (share, adjust) = s.adjust(t);
                (share, adjust.0)
            })
            .unzip();

        let id = self.id.next();

        let receiver_adjust = BatchReceiverAdjust {
            id,
            adjust: receiver_adjust,
        };
        let adjustments = BatchAdjust { id, adjustments };

        Some((receiver_adjust, adjustments))
    }
}

/// Receiver adjustments waiting for [`BatchAdjust`] from the sender.
pub struct BatchReceiverAdjust<F> {
    id: TransferId,
    adjust: Vec<ReceiverAdjust<F>>,
}

impl<F: Field> BatchReceiverAdjust<F> {
    /// Completes the adjustment and returns the new shares.
    ///
    /// # Arguments
    ///
    /// * `batch_adjust` - The sender's adjustments.
    ///
    /// # Returns
    ///
    /// * A vector of [`ReceiverShare`]s containing the new OLE outputs for the receiver.
    pub fn finish_adjust(
        self,
        batch_adjust: BatchAdjust<F>,
    ) -> Result<Vec<ReceiverShare<F>>, OLEError> {
        if self.id != batch_adjust.id {
            return Err(OLEError::WrongId(batch_adjust.id, self.id));
        }

        let receiver_adjust = self.adjust;
        let adjustments = batch_adjust.adjustments;

        if receiver_adjust.len() != adjustments.len() {
            return Err(OLEError::UnequalAdjustments(
                adjustments.len(),
                receiver_adjust.len(),
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
