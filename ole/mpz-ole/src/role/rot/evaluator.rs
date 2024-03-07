use crate::{msg::ROLEeMessage, Check, OLEError, RandomOLEeEvaluate};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_fields::Field;
use mpz_ole_core::role::ot::ROLEeEvaluator as ROLEeCoreEvaluator;
use mpz_ot::RandomOTReceiver;
use serde::{de::DeserializeOwned, Serialize};
use serio::{stream::IoStreamExt, SinkExt};

/// An evaluator for ROLE with errors.
pub struct ROLEeEvaluator<const N: usize, T, F> {
    rot_receiver: T,
    role_core: ROLEeCoreEvaluator<N, F>,
}

impl<const N: usize, T, F: Field> ROLEeEvaluator<N, T, F> {
    /// Create a new [`ROLEeEvaluator`].
    pub fn new(rot_receiver: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            rot_receiver,
            role_core: ROLEeCoreEvaluator::default(),
        }
    }
}

#[async_trait]
impl<const N: usize, T, F: Field + Serialize + DeserializeOwned, C: Context>
    RandomOLEeEvaluate<C, F> for ROLEeEvaluator<N, T, F>
where
    T: RandomOTReceiver<C, bool, [u8; N]> + Send,
    Self: Send,
{
    async fn evaluate_random(
        &mut self,
        ctx: &mut C,
        count: usize,
    ) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let (fi, tfi): (Vec<bool>, Vec<[u8; N]>) = self
            .rot_receiver
            .receive_random(ctx, count * F::BIT_SIZE as usize)
            .await?;

        let channel = ctx.io_mut();

        let (ui, ek): (Vec<F>, Vec<F>) = channel
            .expect_next::<ROLEeMessage<F>>()
            .await?
            .try_into_random_provider_msg()?;

        let dk: Vec<F> = self.role_core.sample_d(count);

        channel
            .send(ROLEeMessage::RandomEvaluatorMsg(dk.clone()))
            .await?;

        let (bk, yk) = self.role_core.generate_output(&fi, &tfi, &ui, &dk, &ek)?;

        Ok((bk, yk))
    }
}
