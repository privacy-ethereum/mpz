use crate::OLECoreError;
use mpz_fields::Field;
use std::marker::PhantomData;

/// An OLE receiver.
pub struct OLEReceiver<F>(PhantomData<F>);

impl<F: Field> OLEReceiver<F> {
    /// Creates a new [`OLEReceiver`].
    pub fn new() -> Self {
        OLEReceiver(PhantomData)
    }

    /// Masks the OLE input with the base OLE input.
    ///
    /// # Arguments
    ///
    /// * `bk_dash` - The base OLE input factors.
    /// * `bk` - The chosen OLE input factors.
    ///
    /// # Returns
    ///
    /// * `vk` - The masked chosen input factors, which will be sent to the sender.
    pub fn create_mask(&self, bk_dash: &[F], bk: &[F]) -> Result<Vec<F>, OLECoreError> {
        if bk_dash.len() != bk.len() {
            return Err(OLECoreError::LengthMismatch(format!(
                "Number of base OLE inputs {} does not match number of OLE inputs {}.",
                bk_dash.len(),
                bk.len(),
            )));
        }

        let vk: Vec<F> = bk_dash.iter().zip(bk).map(|(&d, &b)| b + d).collect();

        Ok(vk)
    }

    /// Generates the OLE output.
    ///
    /// # Arguments
    ///
    /// * `bk` - The OLE input factors.
    /// * `yk_dash` - The base OLE output.
    /// * `uk` - The masked chosen input factors from the sender.
    ///
    /// # Returns
    ///
    /// * `yk` - The OLE output for the receiver.
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

impl<F: Field> Default for OLEReceiver<F> {
    fn default() -> Self {
        Self::new()
    }
}
