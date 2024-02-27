use crate::{msg::ROLEeMessage, Check, OLEError, RandomOLEeProvide};
use async_trait::async_trait;
use futures::SinkExt;
use mpz_ole_core::role::ot::ROLEeProvider as ROLEeCoreProvider;
use mpz_ot::RandomOTSender;
use mpz_share_conversion_core::Field;
use utils_aio::{duplex::Duplex, stream::ExpectStreamExt};

/// A provider for ROLE with errors.
pub struct ROLEeProvider<const N: usize, T, F, IO> {
    channel: IO,
    rot_sender: T,
    role_core: ROLEeCoreProvider<N, F>,
}

impl<const N: usize, T, F: Field, IO> ROLEeProvider<N, T, F, IO> {
    /// Creates a new [`ROLEeProvider`].
    pub fn new(channel: IO, rot_sender: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            channel,
            rot_sender,
            role_core: ROLEeCoreProvider::default(),
        }
    }
}

#[async_trait]
impl<const N: usize, T, F: Field, IO> RandomOLEeProvide<F> for ROLEeProvider<N, T, F, IO>
where
    T: RandomOTSender<[[u8; N]; 2]> + Send,
    IO: Duplex<ROLEeMessage<F>>,
    Self: Send,
{
    async fn provide_random(&mut self, count: usize) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let ti01 = self
            .rot_sender
            .send_random(count * F::BIT_SIZE as usize)
            .await?;

        let (ck, ek) = self.role_core.sample_c_and_e(count);
        let (ui, t0i): (Vec<F>, Vec<F>) = self.role_core.create_correlation(&ti01, &ck)?;

        self.channel
            .send(ROLEeMessage::RandomProviderMsg(ui, ek.clone()))
            .await?;

        let dk: Vec<F> = self
            .channel
            .expect_next()
            .await?
            .try_into_random_evaluator_msg()?;

        let (ak, xk) = self.role_core.generate_output(&t0i, &ck, &dk, &ek)?;

        Ok((ak, xk))
    }
}
