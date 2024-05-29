use crate::{OLEError, OLEErrorKind, OLEReceiver as OLEReceive};
use async_trait::async_trait;
use itybity::ToBits;
use mpz_common::Context;
use mpz_fields::Field;
use mpz_ole_core::msg::{BatchAdjust, MaskedCorrelations};
use mpz_ole_core::OLEReceiver as OLECoreReceiver;
use mpz_ot::RandomOTReceiver;
use serio::stream::IoStreamExt;
use serio::SinkExt;
use serio::{Deserialize, Serialize};

/// OLE receiver.
pub struct OLEReceiver<T, F> {
    rot_receiver: T,
    core: OLECoreReceiver<F>,
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
        }
    }
}

impl<T, F> OLEReceiver<T, F>
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
        T: RandomOTReceiver<Ctx, bool, F> + Send,
    {
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
        let len_requested = b_k.len();

        let (receiver_adjust, adjust) = self.core.adjust(b_k).ok_or_else(|| {
            OLEError::new(
                OLEErrorKind::InsufficientOLEs,
                format!("{} < {}", self.core.cache_size(), len_requested),
            )
        })?;

        let channel = ctx.io_mut();
        channel.send(adjust).await?;
        let adjust = channel.expect_next::<BatchAdjust<F>>().await?;

        let shares = receiver_adjust.finish_adjust(adjust)?;
        let y_k = shares.into_iter().map(|s| s.inner()).collect();

        Ok(y_k)
    }
}
