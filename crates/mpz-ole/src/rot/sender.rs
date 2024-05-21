use crate::{OLEError, OLESender as OLESend};
use async_trait::async_trait;
use itybity::IntoBitIterator;
use mpz_common::Context;
use mpz_fields::Field;
use mpz_ole_core::msg::BatchAdjust;
use mpz_ole_core::OLESender as OLECoreSender;
use mpz_ot::RandomOTSender;
use rand::thread_rng;
use serio::stream::IoStreamExt;
use serio::SinkExt;
use serio::{Deserialize, Serialize};
use std::marker::PhantomData;

/// OLE sender.
pub struct OLESender<const M: usize, const N: usize, T, F, C> {
    rot_sender: T,
    core: OLECoreSender<N, F>,
    context: PhantomData<C>,
}

impl<const M: usize, const N: usize, T, F, C: Context> OLESender<M, N, T, F, C>
where
    T: RandomOTSender<C, [[u8; M]; 2]> + Send,
    F: Field + Serialize + Deserialize,
{
    /// Creates a new sender.
    pub fn new(rot_sender: T) -> Self {
        Self {
            rot_sender,
            core: OLECoreSender::default(),
            context: PhantomData,
        }
    }

    /// Preprocesses OLEs.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of OLEs to preprocess.
    pub async fn preprocess(&mut self, ctx: &mut C, count: usize) -> Result<(), OLEError> {
        let random = {
            let mut rng = thread_rng();
            (0..count).map(|_| F::rand(&mut rng)).collect()
        };

        let random_ot = self
            .rot_sender
            .send_random(ctx, count * F::BIT_SIZE as usize)
            .await?
            .msgs
            .iter()
            .map(|[a, b]| {
                [
                    F::from_lsb0_iter(a.into_iter_lsb0()),
                    F::from_lsb0_iter(b.into_iter_lsb0()),
                ]
            })
            .collect();

        let channel = ctx.io_mut();

        let masks = self.core.preprocess(random, random_ot)?;
        channel.send(masks).await?;

        Ok(())
    }
}

#[async_trait]
impl<const M: usize, const N: usize, T, F, C: Context> OLESend<C, F> for OLESender<M, N, T, F, C>
where
    T: RandomOTSender<C, [[u8; M]; 2]> + Send,
    F: Field + Serialize + Deserialize,
{
    async fn send(&mut self, ctx: &mut C, a_k: Vec<F>) -> Result<Vec<F>, OLEError> {
        let (sender_adjust, adjust) = self.core.adjust(a_k).ok_or(OLEError::InsufficientOLEs)?;

        let channel = ctx.io_mut();
        channel.send(adjust).await?;
        let adjust = channel.expect_next::<BatchAdjust<F>>().await?;

        let shares = sender_adjust.finish_adjust(adjust)?;
        let x_k = shares.into_iter().map(|s| s.inner()).collect();

        Ok(x_k)
    }
}
