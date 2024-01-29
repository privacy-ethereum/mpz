use crate::{
    msg::OLEeMessage,
    ole::role::{into_role_sink, into_role_stream},
    Check, OLEError, OLEeEvaluate, RandomOLEeEvaluate,
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

/// An evaluator for OLEe.
pub struct OLEeEvaluator<const N: usize, T: RandomOLEeEvaluate<F>, F: Field> {
    role_evaluator: T,
    field: PhantomData<F>,
}

impl<const N: usize, T: RandomOLEeEvaluate<F>, F: Field> OLEeEvaluator<N, T, F> {
    /// Create a new [`OLEeEvaluator`].
    pub fn new(role_evaluator: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            role_evaluator,
            field: PhantomData,
        }
    }
}

impl<const N: usize, T: RandomOLEeEvaluate<F>, F: Field> ProtocolMessage
    for OLEeEvaluator<N, T, F>
{
    type Msg = OLEeMessage<T::Msg, F>;
}

#[async_trait]
impl<const N: usize, T, F: Field> OLEeEvaluate<F> for OLEeEvaluator<N, T, F>
where
    T: RandomOLEeEvaluate<F> + Send,
{
    async fn evaluate<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, OLEError> {
        let (bk, yk) = self
            .role_evaluator
            .evaluate_random(
                &mut into_role_sink(sink),
                &mut into_role_stream(stream),
                inputs.len(),
            )
            .await?;

        let vk: Vec<F> = inputs
            .iter()
            .zip(bk.iter().copied())
            .map(|(&i, b)| i + b)
            .collect();

        let uk: Vec<F> = stream
            .expect_next()
            .await?
            .try_into_provider_derand()
            .map_err(|err| OLEError::ROLEeError(err.to_string()))?;
        sink.send(OLEeMessage::EvaluatorDerand(vk)).await?;

        let beta_k: Vec<F> = yk
            .iter()
            .zip(inputs)
            .zip(uk)
            .map(|((&y, i), u)| y + i * u)
            .collect();

        Ok(beta_k)
    }
}
