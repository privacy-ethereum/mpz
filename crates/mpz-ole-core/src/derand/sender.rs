use crate::OLECoreError;
use mpz_fields::Field;
use std::marker::PhantomData;

/// An OLE sender.
pub struct OLESender<F>(PhantomData<F>);

impl<F: Field> OLESender<F> {
    /// Creates a new [`OLESender`].
    pub fn new() -> Self {
        OLESender(PhantomData)
    }

    /// Masks the OLE input with the base OLE input.
    ///
    /// # Arguments
    ///
    /// * `ak_dash` - The base OLE input factors.
    /// * `ak` - The chosen OLE input factors.
    ///
    /// # Returns
    ///
    /// * `uk` - The masked chosen input factors, which will be sent to the receiver.
    pub fn create_mask(&self, ak_dash: &[F], ak: &[F]) -> Result<Vec<F>, OLECoreError> {
        if ak_dash.len() != ak.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Number of base OLE inputs {} does not match number of OLE inputs {}.",
                ak_dash.len(),
                ak.len(),
            )));
        }

        let uk: Vec<F> = ak_dash.iter().zip(ak).map(|(&d, &a)| a + d).collect();

        Ok(uk)
    }

    /// Generates the OLE output.
    ///
    /// # Arguments
    ///
    /// * `ak_dash` - The base OLE input factors.
    /// * `xk_dash` - The base OLE output.
    /// * `vk` - The masked chosen input factors from the receiver.
    ///
    /// # Returns
    ///
    /// * `xk` - The OLE output for the sender.
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
            .zip(ak_dash)
            .zip(vk)
            .map(|((&x, &a), &v)| -(-x + -a * v))
            .collect();

        Ok(xk)
    }
}

impl<F: Field> Default for OLESender<F> {
    fn default() -> Self {
        Self::new()
    }
}
