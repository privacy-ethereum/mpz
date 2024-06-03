use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_fields::Field;
use mpz_ole::OLESender;
use mpz_share_conversion_core::{a2m_convert_sender, m2a_convert, msgs::Masks};
use rand::thread_rng;
use serio::{Deserialize, Serialize, SinkExt};
use std::marker::PhantomData;

/// Sender for share conversion.
pub struct ShareConversionSender<T, F> {
    ole_sender: T,
    phantom: PhantomData<F>,
}

impl<T, F> ShareConversionSender<T, F> {
    /// Creates a new sender.
    pub fn new(ole_sender: T) -> Self {
        Self {
            ole_sender,
            phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<Ctx, F, T> MultiplicativeToAdditive<Ctx, F> for ShareConversionSender<T, F>
where
    T: OLESender<Ctx, F> + Send,
    F: Field + Serialize + Deserialize,
    Ctx: Context,
{
    async fn to_additive(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, ShareConversionError> {
        let ole_output = self.ole_sender.send(ctx, inputs).await?;
        Ok(m2a_convert(ole_output))
    }
}

#[async_trait]
impl<Ctx, F, T> AdditiveToMultiplicative<Ctx, F> for ShareConversionSender<T, F>
where
    T: OLESender<Ctx, F> + Send,
    F: Field + Serialize + Deserialize,
    Ctx: Context,
{
    async fn to_multiplicative(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, ShareConversionError> {
        let random: Vec<F> = {
            let mut rng = thread_rng();
            (0..inputs.len())
                .map(|_| loop {
                    let rand = F::rand(&mut rng);
                    if rand != F::zero() {
                        break rand;
                    }
                })
                .collect()
        };

        let ole_output = self.ole_sender.send(ctx, random.clone()).await?;
        let (output, masks) = a2m_convert_sender(inputs, random, ole_output)?;

        let masks: Masks<F> = masks.into();
        let channel = ctx.io_mut();

        channel.send(masks).await?;

        Ok(output)
    }
}
