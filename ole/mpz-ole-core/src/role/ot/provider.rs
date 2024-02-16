//! An implementation of a ROLEe provider based on random OT

use itybity::IntoBitIterator;
use mpz_share_conversion_core::Field;
use rand::thread_rng;
use std::marker::PhantomData;

use crate::OLECoreError;

use super::Check;

#[derive(Debug)]
/// A ROLEeProvider
pub struct ROLEeProvider<const N: usize, F>(PhantomData<F>);

impl<const N: usize, F: Field> ROLEeProvider<N, F> {
    /// Creates a new [`ROLEeProvider`].
    pub fn new() -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self(PhantomData)
    }

    /// Randomly samples the field elements `c` and `e` `count`-times.
    ///
    /// # Arguments
    ///
    /// * `count` - The batch size, i.e. how many `c`s and `e`s to sample.
    pub fn sample_c_and_e(&self, count: usize) -> (Vec<F>, Vec<F>) {
        let mut rng = thread_rng();

        let ck = (0..count).map(|_| F::rand(&mut rng)).collect();
        let ek = (0..count).map(|_| F::rand(&mut rng)).collect();

        (ck, ek)
    }

    /// Creates the correlation which masks the provider's input `ck`
    ///
    /// # Arguments
    ///
    /// * `ti01` - The random OT messages, which the provider has sent to the evaluator.
    /// * `ck` - The provider's input to the random OLEe.
    ///
    /// # Returns
    ///
    /// * `ui` - The correlations, which will be sent to the evaluator.
    /// * `t0i` - The 0 choice messages of the random OT.
    pub fn create_correlation(
        &self,
        ti01: &[[[u8; N]; 2]],
        ck: &[F],
    ) -> Result<(Vec<F>, Vec<F>), OLECoreError> {
        if ck.len() * F::BIT_SIZE as usize != ti01.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Number of field elements {} does not divide number of OT messages {}.",
                ck.len(),
                ti01.len()
            )));
        }

        let (ui, t0i): (Vec<F>, Vec<F>) = ti01
            .chunks(F::BIT_SIZE as usize)
            .zip(ck)
            .flat_map(|(chunk, &c)| {
                chunk.iter().map(move |[t0, t1]| {
                    let t0 = F::from_lsb0_iter(t0.into_iter_lsb0());
                    let t1 = F::from_lsb0_iter(t1.into_iter_lsb0());
                    (t0 + -t1 + c, t0)
                })
            })
            .unzip();

        Ok((ui, t0i))
    }

    /// Generates the provider's ROLEe input and output
    ///
    /// # Arguments
    ///
    /// * `t0i` - The 0 choice messages of the random OT.
    /// * `ck` - The provider's input to the random OLEe.
    /// * `dk` - The evaluator's input to the random OLEe.
    /// * `ek` - The provider's input to the random OLEe.
    ///
    /// # Returns
    ///
    /// * `ak` - The provider's final ROLEe input factor.
    /// * `xk` - The provider's final ROLEe output summand.
    pub fn generate_output(
        &self,
        t0i: &[F],
        ck: &[F],
        dk: &[F],
        ek: &[F],
    ) -> Result<(Vec<F>, Vec<F>), OLECoreError> {
        if ck.len() * F::BIT_SIZE as usize != t0i.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Number of field elements {} does not divide number of OT messages {}.",
                ck.len(),
                t0i.len(),
            )));
        }

        if ck.len() != dk.len() || dk.len() != ek.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Vectors of field elements have unequal length: ck: {}, dk: {}, ek: {}.",
                ck.len(),
                dk.len(),
                ek.len(),
            )));
        }

        let t0k: Vec<F> = t0i
            .chunks(F::BIT_SIZE as usize)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(F::zero(), |acc, (k, &el)| acc + F::two_pow(k as u32) * el)
            })
            .collect();

        let ak: Vec<F> = ck.iter().zip(dk).map(|(&c, &d)| c + d).collect();

        let xk: Vec<F> = t0k
            .iter()
            .zip(ak.iter().copied())
            .zip(ek)
            .map(|((&t, a), &k)| t + -(a * k))
            .collect();

        Ok((ak, xk))
    }
}

impl<const N: usize, F: Field> Default for ROLEeProvider<N, F> {
    fn default() -> Self {
        Self::new()
    }
}
