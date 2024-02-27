use crate::{msg::OLEeMessage, Check, OLEError, OLEeProvide, RandomOLEeProvide};
use async_trait::async_trait;
use futures::SinkExt;
use mpz_ole_core::ole::role::OLEeProvider as OLEeCoreProvider;
use mpz_share_conversion_core::Field;
use utils_aio::{
    sink::IoSink,
    stream::{ExpectStreamExt, IoStream},
};

/// A provider for OLE with errors.
pub struct OLEeProvider<const N: usize, T: RandomOLEeProvide<F>, F: Field> {
    role_provider: T,
    ole_core: OLEeCoreProvider<F>,
}

impl<const N: usize, T: RandomOLEeProvide<F>, F: Field> OLEeProvider<N, T, F> {
    /// Creates a new [`OLEeProvider`].
    pub fn new(role_provider: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            role_provider,
            ole_core: OLEeCoreProvider::default(),
        }
    }
}

#[async_trait]
impl<const N: usize, T, F: Field> OLEeProvide<F> for OLEeProvider<N, T, F>
where
    T: RandomOLEeProvide<F> + Send,
    Self: Send,
{
    async fn provide(&mut self, factors: Vec<F>) -> Result<Vec<F>, OLEError> {
        let (ak_dash, xk_dash) = self.role_provider.provide_random(factors.len()).await?;

        let uk: Vec<F> = self.ole_core.create_mask(&ak_dash, &factors)?;

        sink.send(OLEeMessage::ProviderDerand(uk)).await?;
        let vk: Vec<F> = stream.expect_next().await?.try_into_evaluator_derand()?;

        let x_k: Vec<F> = self
            .ole_core
            .generate_output(&ak_dash, &xk_dash, &vk)
            .unwrap();

        Ok(x_k)
    }
}
