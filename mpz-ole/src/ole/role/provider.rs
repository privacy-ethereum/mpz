use crate::{
    msg::OLEeMessage,
    ole::role::{into_role_sink, into_role_stream},
    Check, OLEError, OLEeProvide, RandomOLEeProvide,
};
use async_trait::async_trait;
use futures::SinkExt;
use mpz_core::ProtocolMessage;
use mpz_share_conversion_core::Field;
use std::marker::PhantomData;
use utils_aio::{
    sink::IoSink,
    stream::{ExpectStreamExt, IoStream},
};

/// A provider for various OLE constructions.
pub struct OLEeProvider<const N: usize, T: RandomOLEeProvide<F>, F: Field> {
    role_provider: T,
    field: PhantomData<F>,
}

impl<const N: usize, T: RandomOLEeProvide<F>, F: Field> OLEeProvider<N, T, F> {
    /// Create a new [`OLEeProvider`].
    pub fn new(role_provider: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            role_provider,
            field: PhantomData,
        }
    }
}

impl<const N: usize, T: RandomOLEeProvide<F>, F: Field> ProtocolMessage for OLEeProvider<N, T, F> {
    type Msg = OLEeMessage<T::Msg, F>;
}

#[async_trait]
impl<const N: usize, T, F: Field> OLEeProvide<F> for OLEeProvider<N, T, F>
where
    T: RandomOLEeProvide<F> + Send,
    Self: Send,
{
    async fn provide<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        factors: Vec<F>,
    ) -> Result<Vec<F>, OLEError> {
        let (ak, xk) = self
            .role_provider
            .provide_random(
                &mut into_role_sink(sink),
                &mut into_role_stream(stream),
                factors.len(),
            )
            .await?;

        let uk: Vec<F> = factors
            .iter()
            .zip(ak.iter().copied())
            .map(|(&f, a)| a + f)
            .collect();

        sink.send(OLEeMessage::ProviderDerand(uk)).await?;
        let vk: Vec<F> = stream
            .expect_next()
            .await?
            .try_into_evaluator_derand()
            .map_err(|err| OLEError::ROLEeError(err.to_string()))?;

        let alpha_k: Vec<F> = xk
            .iter()
            .zip(ak)
            .zip(vk)
            .map(|((&x, a), v)| x + -a * v)
            .collect();

        Ok(alpha_k)
    }
}
