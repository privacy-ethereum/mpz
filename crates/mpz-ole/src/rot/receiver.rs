use crate::{OLEError, OLEErrorKind, OLEReceiver as OLEReceive};
use async_trait::async_trait;
use hybrid_array::Array;
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
        T: RandomOTReceiver<Ctx, bool, Array<u8, F::ByteSize>> + Send,
    {
        let random_ot = self
            .rot_receiver
            .receive_random(ctx, count * F::BIT_SIZE)
            .await?;

        let rot_msg: Vec<F> = random_ot
            .msgs
            .into_iter()
            .map(|f| F::try_from(f))
            .collect::<Result<Vec<F>, _>>()?;

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
        let (receiver_adjust, adjust) = self.core.adjust(b_k).ok_or_else(|| {
            OLEError::new(
                OLEErrorKind::InsufficientOLEs,
                "Not enough OLEs available".into(),
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
