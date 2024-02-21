use crate::OLECoreError;
use mpz_share_conversion_core::Field;
use std::marker::PhantomData;

/// An evaluator for OLE with errors.
pub struct OLEeEvaluator<F>(PhantomData<F>);

impl<F: Field> OLEeEvaluator<F> {
    /// Creates a new [`OLEeEvaluator`].
    pub fn new() -> Self {
        OLEeEvaluator(PhantomData)
    }

    /// Masks the OLEe input with the ROLEe input.
    ///
    /// # Arguments
    ///
    /// * `bk_dash` - The ROLEe input factors.
    /// * `bk` - The chosen OLEe input factors.
    ///
    /// # Returns
    ///
    /// * `vk` - The masked chosen input factors, which will be sent to the provider.
    pub fn create_mask(&self, bk_dash: &[F], bk: &[F]) -> Result<Vec<F>, OLECoreError> {
        if bk_dash.len() != bk.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Number of ROLE inputs {} does not match number of OLE inputs {}.",
                bk_dash.len(),
                bk.len(),
            )));
        }

        let vk: Vec<F> = bk_dash.iter().zip(bk).map(|(&d, &b)| b + d).collect();

        Ok(vk)
    }

    /// Generates the OLEe output.
    ///
    /// # Arguments
    ///
    /// * `bk` - The OLEe input factors.
    /// * `yk_dash` - The ROLEe output.
    /// * `uk` - The masked chosen input factors from the provider.
    ///
    /// # Returns
    ///
    /// * `yk` - The OLEe output for the evaluator.
    pub fn generate_output(
        &self,
        bk: &[F],
        yk_dash: &[F],
        uk: &[F],
    ) -> Result<Vec<F>, OLECoreError> {
        if bk.len() != yk_dash.len() || yk_dash.len() != uk.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Length of field element vectors does not match. bk: {}, yk_dash: {}, uk: {}",
                bk.len(),
                yk_dash.len(),
                uk.len(),
            )));
        }

        let yk: Vec<F> = yk_dash
            .iter()
            .zip(bk)
            .zip(uk)
            .map(|((&y, &b), &u)| y + b * u)
            .collect();

        Ok(yk)
    }
}

impl<F: Field> Default for OLEeEvaluator<F> {
    fn default() -> Self {
        Self::new()
    }
}
