use super::Check;
use crate::OLECoreError;
use itybity::{IntoBitIterator, ToBits};
use mpz_fields::Field;
use std::marker::PhantomData;

/// An receiver for COPEe.
pub struct COPEeReceiver<const N: usize, F>(PhantomData<F>);

impl<const N: usize, F: Field> COPEeReceiver<N, F> {
    /// Creates a new [`COPEeReceiver`].
    pub fn new() -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self(PhantomData)
    }

    /// Generates the receiver's OLE input and output.
    ///
    /// # Arguments
    ///
    /// * `delta_k` - The receiver's inputs to the OLE.
    /// * `t_delta_i` - The receiver's random OT messages.
    /// * `ui` - The correlations, sent by the sender.
    ///
    /// # Returns
    ///
    /// * `qk` - The receiver's final OLE output summands.
    pub fn generate(
        &self,
        delta_k: &[F],
        t_delta_i: &[[u8; N]],
        ui: &[F],
    ) -> Result<Vec<F>, OLECoreError> {
        if delta_k.len() * F::BIT_SIZE as usize != t_delta_i.len() || t_delta_i.len() != ui.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Number of choices {}, received OT messages {} and received correlations {} are not equal.",
                delta_k.len(),
                t_delta_i.len(),
                ui.len(),
            )));
        }

        let delta_i: Vec<bool> = delta_k.iter_lsb0().collect();

        let qk: Vec<F> = delta_i
            .chunks(F::BIT_SIZE as usize)
            .zip(t_delta_i.chunks(F::BIT_SIZE as usize))
            .zip(ui.chunks(F::BIT_SIZE as usize))
            .map(|((delta, t), u)| {
                delta.iter().zip(t).zip(u).enumerate().fold(
                    F::zero(),
                    |acc, (i, ((&delta, t), &u))| {
                        let delta = if delta { F::one() } else { F::zero() };
                        acc + F::two_pow(i as u32)
                            * (delta * u + F::from_lsb0_iter(t.into_iter_lsb0()))
                    },
                )
            })
            .collect();

        Ok(qk)
    }
}

impl<const N: usize, F: Field> Default for COPEeReceiver<N, F> {
    fn default() -> Self {
        Self::new()
    }
}
