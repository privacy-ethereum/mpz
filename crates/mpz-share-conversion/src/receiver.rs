use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_fields::Field;
use mpz_ole::OLEReceiver;
use mpz_share_conversion_core::{a2m_convert_receiver, msgs::Masks, A2MMasks};
use serio::{stream::IoStreamExt, Deserialize, Serialize};
use std::marker::PhantomData;

/// Receiver for share conversion.
pub struct ShareConversionReceiver<T, F> {
    ole_receiver: T,
    phantom: PhantomData<F>,
}

impl<T, F> ShareConversionReceiver<T, F> {
    /// Creates a new receiver.
    pub fn new(ole_receiver: T) -> Self {
        Self {
            ole_receiver,
            phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<Ctx, F, T> MultiplicativeToAdditive<Ctx, F> for ShareConversionReceiver<T, F>
where
    T: OLEReceiver<Ctx, F> + Send,
    F: Field + Serialize + Deserialize,
    Ctx: Context,
{
    async fn to_additive(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, ShareConversionError> {
        self.ole_receiver
            .receive(ctx, inputs)
            .await
            .map_err(ShareConversionError::from)
    }
}

#[async_trait]
impl<Ctx, F, T> AdditiveToMultiplicative<Ctx, F> for ShareConversionReceiver<T, F>
where
    T: OLEReceiver<Ctx, F> + Send,
    F: Field + Serialize + Deserialize,
    Ctx: Context,
{
    async fn to_multiplicative(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, ShareConversionError> {
        let ole_output = self.ole_receiver.receive(ctx, inputs).await?;

        let channel = ctx.io_mut();
        let masks: A2MMasks<F> = channel.expect_next::<Masks<F>>().await?.into();

        a2m_convert_receiver(masks, ole_output).map_err(ShareConversionError::from)
    }
}
