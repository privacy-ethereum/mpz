use std::mem;

use crate::{OLEError, OLEErrorKind, OLEReceiver as OLEReceive};
use async_trait::async_trait;
use itybity::ToBits;
use mpz_common::{Allocate, Context, Preprocess};
use mpz_fields::Field;
use mpz_ole_core::{
    msg::{BatchAdjust, MaskedCorrelations},
    BatchReceiverAdjust, OLEReceiver as OLECoreReceiver,
};
use mpz_ot::{OTError, RandomOTReceiver};
use serio::{stream::IoStreamExt, Deserialize, Serialize, SinkExt};

/// OLE receiver.
#[derive(Debug)]
pub struct OLEReceiver<T, F> {
    rot_receiver: T,
    core: OLECoreReceiver<F>,
    alloc: usize,
}

impl<T, F> OLEReceiver<T, F>
where
    F: Field + Serialize + Deserialize,
{
    /// Creates a new receiver.
    pub fn new(rot_receiver: T) -> Self {
        Self {
            rot_receiver,
            core: OLECoreReceiver::default(),
            alloc: 0,
        }
    }

    pub(crate) fn adjust(
        &mut self,
        inputs: Vec<F>,
    ) -> Result<(BatchReceiverAdjust<F>, BatchAdjust<F>), OLEError> {
        let len = inputs.len();
        self.core.adjust(inputs).ok_or_else(|| {
            OLEError::new(
                OLEErrorKind::InsufficientOLEs,
                format!("{} < {}", self.core.cache_size(), len),
            )
        })
    }
}

impl<T, F> Allocate for OLEReceiver<T, F>
where
    T: Allocate,
    F: Field,
{
    fn alloc(&mut self, count: usize) {
        self.rot_receiver.alloc(count * F::BIT_SIZE);
        self.alloc += count;
    }
}

#[async_trait]
impl<Ctx, T, F> Preprocess<Ctx> for OLEReceiver<T, F>
where
    Ctx: Context,
    T: Preprocess<Ctx, Error = OTError> + RandomOTReceiver<Ctx, bool, F> + Send,
    F: Field + Serialize + Deserialize,
{
    type Error = OLEError;

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), OLEError> {
        let count = mem::take(&mut self.alloc);
        if count == 0 {
            return Ok(());
        }

        self.rot_receiver.preprocess(ctx).await?;

        let random_ot = self
            .rot_receiver
            .receive_random(ctx, count * F::BIT_SIZE)
            .await?;

        let rot_msg: Vec<F> = random_ot.msgs;

        let rot_choices: Vec<F> = random_ot
            .choices
            .chunks(F::BIT_SIZE)
            .map(|choice| F::from_lsb0_iter(choice.iter_lsb0()))
            .collect();

        let channel = ctx.io_mut();
        let masks = channel.expect_next::<MaskedCorrelations<F>>().await?;

        self.core.preprocess(rot_choices, rot_msg, masks)?;
        Ok(())
    }
}

#[async_trait]
impl<T: Send, F, Ctx: Context> OLEReceive<Ctx, F> for OLEReceiver<T, F>
where
    F: Field + Serialize + Deserialize,
{
    async fn receive(&mut self, ctx: &mut Ctx, b_k: Vec<F>) -> Result<Vec<F>, OLEError> {
        let (receiver_adjust, adjust) = self.adjust(b_k)?;

        let channel = ctx.io_mut();
        channel.send(adjust).await?;
        let adjust = channel.expect_next::<BatchAdjust<F>>().await?;

        let shares = receiver_adjust.finish_adjust(adjust)?;
        let y_k = shares.into_iter().map(|s| s.inner()).collect();

        Ok(y_k)
    }
}
