use mpz_share_conversion_core::Field;
use std::marker::PhantomData;

use crate::OLECoreError;

/// A provider for OLE with errors
pub struct OLEeProvider<F>(PhantomData<F>);

impl<F: Field> OLEeProvider<F> {
    /// Creates a new [`OLEeProvider`].
    pub fn new() -> Self {
        OLEeProvider(PhantomData)
    }

    /// Masks the OLEe input with the ROLEe input
    ///
    /// # Arguments
    ///
    /// * `ak_dash` - The ROLEe input factors
    /// * `ak` - The chosen OLEe input
    ///
    /// # Returns
    ///
    /// * `uk` - The masked chosen input factors, which will be sent to the evaluator
    pub fn create_mask(&self, ak_dash: &[F], ak: &[F]) -> Result<Vec<F>, OLECoreError> {
        if ak_dash.len() != ak.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Number of ROLE inputs {} does not match number of OLE inputs {}.",
                ak_dash.len(),
                ak.len(),
            )));
        }

        let uk: Vec<F> = ak_dash
            .iter()
            .zip(ak.iter().copied())
            .map(|(&d, a)| a + d)
            .collect();

        Ok(uk)
    }

    /// Generates the OLEe output
    ///
    /// # Arguments
    ///
    /// * `ak_dash` - The ROLEe input
    /// * `xk_dash` - The ROLEe output
    /// * `vk` - The masked chosen input factors from the evaluator
    ///
    /// # Returns
    ///
    /// * `xk` - The OLEe output for the provider
    pub fn generate_output(
        &self,
        ak_dash: &[F],
        xk_dash: &[F],
        vk: &[F],
    ) -> Result<Vec<F>, OLECoreError> {
        if ak_dash.len() != xk_dash.len() || xk_dash.len() != vk.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Length of field element vectors does not match. ak: {}, xk_dash: {}, vk: {}",
                ak_dash.len(),
                xk_dash.len(),
                vk.len(),
            )));
        }

        let xk: Vec<F> = xk_dash
            .iter()
            .zip(ak_dash.iter().copied())
            .zip(vk.iter().copied())
            .map(|((&x, a), v)| -(-x + -a * v))
            .collect();

        Ok(xk)
    }
}

impl<F: Field> Default for OLEeProvider<F> {
    fn default() -> Self {
        Self::new()
    }
}
