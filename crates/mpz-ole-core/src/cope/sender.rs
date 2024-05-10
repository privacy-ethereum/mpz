use super::Check;
use crate::OLECoreError;
use itybity::IntoBitIterator;
use mpz_fields::Field;
use std::marker::PhantomData;

/// A sender for COPEe.
pub struct COPEeSender<const N: usize, F>(PhantomData<F>);

impl<const N: usize, F: Field> COPEeSender<N, F> {
    /// Creates a new [`COPEeSender`].
    pub fn new() -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self(PhantomData)
    }

    /// Creates  and returns correlations from random OT messages. Also returns the sender's OLE output.
    ///
    /// # Arguments
    ///
    /// * `ti01` - The OT messages, which the sender has sent to the receiver.
    /// * `xk` - The sender's inputs to the OLE.
    ///
    /// # Returns
    ///
    /// * `ui` - The correlations, which will be sent to the receiver.
    /// * `t0k` - The sender's final OLE output summands.
    pub fn generate(
        &self,
        ti01: &[[[u8; N]; 2]],
        xk: &[F],
    ) -> Result<(Vec<F>, Vec<F>), OLECoreError> {
        if xk.len() * F::BIT_SIZE as usize != ti01.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Number of field elements {} does not divide number of OT messages {}.",
                xk.len(),
                ti01.len()
            )));
        }

        let (ui, t0i): (Vec<F>, Vec<F>) = ti01
            .chunks(F::BIT_SIZE as usize)
            .zip(xk)
            .flat_map(|(chunk, &x)| {
                chunk.iter().map(move |[t0, t1]| {
                    let t0 = F::from_lsb0_iter(t0.into_iter_lsb0());
                    let t1 = F::from_lsb0_iter(t1.into_iter_lsb0());
                    (t0 + -t1 + x, t0)
                })
            })
            .unzip();

        let t0k: Vec<F> = t0i
            .chunks(F::BIT_SIZE as usize)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(F::zero(), |acc, (k, &t0)| acc + F::two_pow(k as u32) * t0)
            })
            .collect();

        Ok((ui, t0k))
    }
}

impl<const N: usize, F: Field> Default for COPEeSender<N, F> {
    fn default() -> Self {
        Self::new()
    }
}
