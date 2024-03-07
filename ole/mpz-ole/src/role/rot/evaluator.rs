use crate::{msg::ROLEeMessage, Check, OLEError, RandomOLEeEvaluate};
use async_trait::async_trait;
use futures::SinkExt;
use mpz_fields::Field;
use mpz_ole_core::role::ot::ROLEeEvaluator as ROLEeCoreEvaluator;
use mpz_ot::RandomOTReceiver;
use utils_aio::{duplex::Duplex, stream::ExpectStreamExt};

/// An evaluator for ROLE with errors.
pub struct ROLEeEvaluator<const N: usize, T, F, IO> {
    channel: IO,
    rot_receiver: T,
    role_core: ROLEeCoreEvaluator<N, F>,
}

impl<const N: usize, T, F: Field, IO> ROLEeEvaluator<N, T, F, IO> {
    /// Create a new [`ROLEeEvaluator`].
    pub fn new(channel: IO, rot_receiver: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            channel,
            rot_receiver,
            role_core: ROLEeCoreEvaluator::default(),
        }
    }
}

#[async_trait]
impl<const N: usize, T, F: Field, IO> RandomOLEeEvaluate<F> for ROLEeEvaluator<N, T, F, IO>
where
    T: RandomOTReceiver<bool, [u8; N]> + Send,
    IO: Duplex<ROLEeMessage<F>>,
    Self: Send,
{
    async fn evaluate_random(&mut self, count: usize) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let (fi, tfi): (Vec<bool>, Vec<[u8; N]>) = self
            .rot_receiver
            .receive_random(count * F::BIT_SIZE as usize)
            .await?;

        let (ui, ek): (Vec<F>, Vec<F>) = self
            .channel
            .expect_next()
            .await?
            .try_into_random_provider_msg()?;

        let dk: Vec<F> = self.role_core.sample_d(count);

        self.channel
            .send(ROLEeMessage::RandomEvaluatorMsg(dk.clone()))
            .await?;

        let (bk, yk) = self.role_core.generate_output(&fi, &tfi, &ui, &dk, &ek)?;

        Ok((bk, yk))
    }
}
