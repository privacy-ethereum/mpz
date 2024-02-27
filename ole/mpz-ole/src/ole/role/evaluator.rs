use crate::{msg::OLEeMessage, Check, OLEError, OLEeEvaluate, RandomOLEeEvaluate};
use async_trait::async_trait;
use futures::SinkExt;
use mpz_ole_core::ole::role::OLEeEvaluator as OLEeCoreEvaluator;
use mpz_share_conversion_core::Field;
use utils_aio::{duplex::Duplex, stream::ExpectStreamExt};

/// An evaluator for OLE with errors.
pub struct OLEeEvaluator<const N: usize, T, F, IO> {
    channel: IO,
    role_evaluator: T,
    ole_core: OLEeCoreEvaluator<F>,
}

impl<const N: usize, T, F: Field, IO> OLEeEvaluator<N, T, F, IO> {
    /// Creates a new [`OLEeEvaluator`].
    pub fn new(channel: IO, role_evaluator: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            channel,
            role_evaluator,
            ole_core: OLEeCoreEvaluator::default(),
        }
    }
}

#[async_trait]
impl<const N: usize, T, F: Field, IO> OLEeEvaluate<F> for OLEeEvaluator<N, T, F, IO>
where
    IO: Duplex<OLEeMessage<F>>,
    T: RandomOLEeEvaluate<F> + Send,
{
    async fn evaluate(&mut self, inputs: Vec<F>) -> Result<Vec<F>, OLEError> {
        let (bk_dash, yk_dash) = self.role_evaluator.evaluate_random(inputs.len()).await?;

        let vk: Vec<F> = self.ole_core.create_mask(&bk_dash, &inputs)?;

        let uk: Vec<F> = self
            .channel
            .expect_next()
            .await?
            .try_into_provider_derand()?;
        self.channel.send(OLEeMessage::EvaluatorDerand(vk)).await?;

        let yk: Vec<F> = self.ole_core.generate_output(&inputs, &yk_dash, &uk)?;

        Ok(yk)
    }
}
