use crate::{OLEError, OLEErrorKind, OLESender as OLESend};
use async_trait::async_trait;
use mpz_common::Context;
use mpz_fields::Field;
use mpz_ole_core::msg::BatchAdjust;
use mpz_ole_core::OLESender as OLECoreSender;
use mpz_ot::RandomOTSender;
use rand::thread_rng;
use serio::stream::IoStreamExt;
use serio::SinkExt;
use serio::{Deserialize, Serialize};

/// OLE sender.
pub struct OLESender<T, F> {
    rot_sender: T,
    core: OLECoreSender<F>,
}

impl<T, F> OLESender<T, F>
where
    F: Field + Serialize + Deserialize,
{
    /// Creates a new sender.
    pub fn new(rot_sender: T) -> Self {
        Self {
            rot_sender,
            core: OLECoreSender::default(),
        }
    }
}

impl<T, F> OLESender<T, F>
where
    F: Field + Serialize + Deserialize,
{
    /// Preprocesses OLEs.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of OLEs to preprocess.
    pub async fn preprocess<Ctx: Context>(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<(), OLEError>
    where
        T: RandomOTSender<Ctx, [F; 2]> + Send,
    {
        let random = {
            let mut rng = thread_rng();
            (0..count).map(|_| F::rand(&mut rng)).collect()
        };

        let random_ot: Vec<[F; 2]> = self
            .rot_sender
            .send_random(ctx, count * F::BIT_SIZE)
            .await?
            .msgs;

        let channel = ctx.io_mut();

        let masks = self.core.preprocess(random, random_ot)?;
        channel.send(masks).await?;

        Ok(())
    }
}

#[async_trait]
impl<T: Send, F, Ctx: Context> OLESend<Ctx, F> for OLESender<T, F>
where
    F: Field + Serialize + Deserialize,
{
    async fn send(&mut self, ctx: &mut Ctx, a_k: Vec<F>) -> Result<Vec<F>, OLEError> {
        let len_requested = a_k.len();

        let (sender_adjust, adjust) = self.core.adjust(a_k).ok_or_else(|| {
            OLEError::new(
                OLEErrorKind::InsufficientOLEs,
                format!("{} < {}", self.core.cache_size(), len_requested),
            )
        })?;
        let channel = ctx.io_mut();
        channel.send(adjust).await?;
        let adjust = channel.expect_next::<BatchAdjust<F>>().await?;

        let shares = sender_adjust.finish_adjust(adjust)?;
        let x_k = shares.into_iter().map(|s| s.inner()).collect();

        Ok(x_k)
    }
}
