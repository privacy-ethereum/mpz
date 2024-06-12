use std::mem;

use crate::{OLEError, OLEErrorKind, OLESender as OLESend};
use async_trait::async_trait;
use mpz_common::{Allocate, Context, Preprocess};
use mpz_fields::Field;
use mpz_ole_core::{msg::BatchAdjust, BatchSenderAdjust, OLESender as OLECoreSender};
use mpz_ot::{OTError, RandomOTSender};
use rand::thread_rng;
use serio::{stream::IoStreamExt, Deserialize, Serialize, SinkExt};

/// OLE sender.
#[derive(Debug)]
pub struct OLESender<T, F> {
    rot_sender: T,
    core: OLECoreSender<F>,
    alloc: usize,
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
            alloc: 0,
        }
    }

    pub(crate) fn adjust(
        &mut self,
        inputs: Vec<F>,
    ) -> Result<(BatchSenderAdjust<F>, BatchAdjust<F>), OLEError> {
        let len = inputs.len();
        self.core.adjust(inputs).ok_or_else(|| {
            OLEError::new(
                OLEErrorKind::InsufficientOLEs,
                format!("{} < {}", self.core.cache_size(), len),
            )
        })
    }
}

impl<T, F> Allocate for OLESender<T, F>
where
    T: Allocate,
    F: Field,
{
    fn alloc(&mut self, count: usize) {
        self.rot_sender.alloc(count * F::BIT_SIZE);
        self.alloc += count;
    }
}

#[async_trait]
impl<Ctx, T, F> Preprocess<Ctx> for OLESender<T, F>
where
    Ctx: Context,
    T: Allocate + Preprocess<Ctx, Error = OTError> + RandomOTSender<Ctx, [F; 2]> + Send,
    F: Field + Serialize + Deserialize,
{
    type Error = OLEError;

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), OLEError> {
        let count = mem::take(&mut self.alloc);
        if count == 0 {
            return Ok(());
        }

        self.rot_sender.preprocess(ctx).await?;

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
        let (sender_adjust, adjust) = self.adjust(a_k)?;

        let channel = ctx.io_mut();
        channel.send(adjust).await?;
        let adjust = channel.expect_next::<BatchAdjust<F>>().await?;

        let shares = sender_adjust.finish_adjust(adjust)?;
        let x_k = shares.into_iter().map(|s| s.inner()).collect();

        Ok(x_k)
    }
}
