use crate::{OLEError, OLEReceiver as OLEReceive};
use async_trait::async_trait;
use itybity::ToBits;
use mpz_common::Context;
use mpz_fields::Field;
use mpz_ole_core::msg::{BatchAdjust, MaskedInputs};
use mpz_ole_core::OLEReceiver as OLECoreReceiver;
use mpz_ot::RandomOTReceiver;
use serio::stream::IoStreamExt;
use serio::SinkExt;
use serio::{Deserialize, Serialize};
use std::marker::PhantomData;

/// OLE receiver.
pub struct OLEReceiver<const M: usize, const N: usize, T, F, C> {
    rot_receiver: T,
    core: OLECoreReceiver<N, F>,
    context: PhantomData<C>,
}

impl<const M: usize, const N: usize, T, F, C: Context> OLEReceiver<M, N, T, F, C>
where
    T: RandomOTReceiver<C, bool, [u8; M]> + Send,
    F: Field + Serialize + Deserialize,
{
    /// Creates a new receiver.
    pub fn new(rot_receiver: T) -> Self {
        Self {
            rot_receiver,
            core: OLECoreReceiver::default(),
            context: PhantomData,
        }
    }

    /// Preprocesses OLEs.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of OLEs to preprocess.
    pub async fn preprocess(&mut self, ctx: &mut C, count: usize) -> Result<(), OLEError> {
        let random_ot = self
            .rot_receiver
            .receive_random(ctx, count * F::BIT_SIZE as usize)
            .await?;

        let rot_msg: Vec<F> = random_ot
            .msgs
            .iter()
            .map(|f| F::from_lsb0_iter(f.iter_lsb0()))
            .collect();

        let rot_choices: Vec<F> = random_ot
            .choices
            .chunks(F::BIT_SIZE as usize)
            .map(|choice| F::from_lsb0_iter(choice.iter_lsb0()))
            .collect();

        let channel = ctx.io_mut();
        let masks = channel.expect_next::<MaskedInputs<F>>().await?;

        self.core.preprocess(rot_choices, rot_msg, masks)?;
        Ok(())
    }
}

#[async_trait]
impl<const M: usize, const N: usize, T, F, C: Context> OLEReceive<C, F>
    for OLEReceiver<M, N, T, F, C>
where
    T: RandomOTReceiver<C, bool, [u8; M]> + Send,
    F: Field + Serialize + Deserialize,
{
    async fn receive(&mut self, ctx: &mut C, b_k: Vec<F>) -> Result<Vec<F>, OLEError> {
        let (receiver_adjust, adjust) = self.core.adjust(b_k).ok_or(OLEError::InsufficientOLEs)?;

        let channel = ctx.io_mut();
        channel.send(adjust).await?;
        let adjust = channel.expect_next::<BatchAdjust<F>>().await?;

        let shares = receiver_adjust.finish_adjust(adjust)?;
        let y_k = shares.into_iter().map(|s| s.inner()).collect();

        Ok(y_k)
    }
}
