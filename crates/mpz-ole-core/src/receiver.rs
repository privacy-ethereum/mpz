//! Receiver implementation.

use crate::{
    core::{ReceiverAdjust, ReceiverShare, ShareAdjust},
    msg::{BatchAdjust, MaskedCorrelations},
    OLEError, TransferId,
};
use mpz_fields::Field;
use std::collections::VecDeque;

/// A receiver for batched OLE.
#[derive(Debug)]
pub struct OLEReceiver<F> {
    id: TransferId,
    cache: VecDeque<ReceiverShare<F>>,
}

impl<F: Field> Default for OLEReceiver<F> {
    fn default() -> Self {
        OLEReceiver {
            id: TransferId::default(),
            cache: VecDeque::default(),
        }
    }
}

impl<F: Field> OLEReceiver<F> {
    /// Generates new OLEs and stores them internally.
    ///
    /// # Arguments
    ///
    /// * `input` - The receiver's OLE input shares.
    /// * `random` - Uniformly random field elements.
    /// * `masked` - The correlations from the sender.
    pub fn preprocess(
        &mut self,
        input: Vec<F>,
        random: Vec<F>,
        masked: MaskedCorrelations<F>,
    ) -> Result<(), OLEError> {
        let masks = masked.try_into()?;
        let shares = ReceiverShare::new_vec(input, random, masks)?;

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
    /// * [`BatchAdjust`] which needs to be sent to the sender.
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
            .zip(adjustments)
            .map(|(s, a)| s.finish(ShareAdjust(a)))
            .collect();

        Ok(shares)
    }
}
