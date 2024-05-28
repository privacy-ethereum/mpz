//! Sender implementation.

use crate::{
    core::{SenderAdjust, SenderShare, ShareAdjust},
    msg::{BatchAdjust, MaskedCorrelations},
    OLEError, TransferId,
};
use mpz_fields::Field;
use std::collections::VecDeque;

/// A sender for batched OLE.
#[derive(Debug)]
pub struct OLESender<F> {
    id: TransferId,
    cache: VecDeque<SenderShare<F>>,
}

impl<F: Field> Default for OLESender<F> {
    fn default() -> Self {
        OLESender {
            id: TransferId::default(),
            cache: VecDeque::default(),
        }
    }
}

impl<F: Field> OLESender<F> {
    /// Generates new OLEs and stores them internally.
    ///
    /// # Arguments
    ///
    /// * `input` - The sender's OLE input shares.
    /// * `random` - Uniformly random field elements for the correlation.
    ///
    /// # Returns
    ///
    /// * [`MaskedCorrelations`], which are to be sent to the receiver.
    pub fn preprocess(
        &mut self,
        input: Vec<F>,
        random: Vec<[F; 2]>,
    ) -> Result<MaskedCorrelations<F>, OLEError> {
        let (shares, masked) = SenderShare::new_vec(input, random)?;
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
    /// * [`BatchSenderAdjust`] which needs to be converted by [`BatchSenderAdjust::finish_adjust`].
    /// * [`BatchAdjust`] which needs to be sent to the receiver.
    pub fn adjust(&mut self, targets: Vec<F>) -> Option<(BatchSenderAdjust<F>, BatchAdjust<F>)> {
        let shares = self.consume(targets.len())?;
        let (sender_adjust, adjustments) = shares
            .into_iter()
            .zip(targets)
            .map(|(s, t)| {
                let (share, adjust) = s.adjust(t);
                (share, adjust.0)
            })
            .unzip();

        let id = self.id.next();

        let sender_adjust = BatchSenderAdjust {
            id,
            adjust: sender_adjust,
        };
        let adjustments = BatchAdjust { id, adjustments };

        Some((sender_adjust, adjustments))
    }

    /// Returns the number of preprocessed OLEs that are available.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

/// Sender adjustments waiting for [`BatchAdjust`] from the receiver.
pub struct BatchSenderAdjust<F> {
    id: TransferId,
    adjust: Vec<SenderAdjust<F>>,
}

impl<F: Field> BatchSenderAdjust<F> {
    /// Completes the adjustment and returns the new shares.
    ///
    /// # Arguments
    ///
    /// * `batch_adjust` - The receiver's adjustments.
    ///
    /// # Returns
    ///
    /// * A vector of [`SenderShare`]s containing the new OLE outputs for the sender.
    pub fn finish_adjust(
        self,
        batch_adjust: BatchAdjust<F>,
    ) -> Result<Vec<SenderShare<F>>, OLEError> {
        if self.id != batch_adjust.id {
            return Err(OLEError::WrongId(batch_adjust.id, self.id));
        }

        let sender_adjust = self.adjust;
        let adjustments = batch_adjust.adjustments;

        if sender_adjust.len() != adjustments.len() {
            return Err(OLEError::UnequalAdjustments(
                adjustments.len(),
                sender_adjust.len(),
            ));
        }

        let shares = sender_adjust
            .into_iter()
            .zip(adjustments)
            .map(|(s, a)| s.finish(ShareAdjust(a)))
            .collect();

        Ok(shares)
    }
}
