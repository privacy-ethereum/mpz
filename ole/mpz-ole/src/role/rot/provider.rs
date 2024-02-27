use crate::{msg::ROLEeMessage, Check, OLEError, RandomOLEeProvide};
use async_trait::async_trait;
use futures::SinkExt;
use mpz_core::ProtocolMessage;
use mpz_ole_core::role::ot::ROLEeProvider as ROLEeCoreProvider;
use mpz_ot::RandomOTSender;
use mpz_share_conversion_core::Field;
use utils_aio::{
    sink::IoSink,
    stream::{ExpectStreamExt, IoStream},
};

/// A provider for ROLE with errors.
pub struct ROLEeProvider<const N: usize, T: RandomOTSender<[[u8; N]; 2]>, F> {
    rot_sender: T,
    role_core: ROLEeCoreProvider<N, F>,
}

impl<const N: usize, T: RandomOTSender<[[u8; N]; 2]>, F: Field> ROLEeProvider<N, T, F> {
    /// Creates a new [`ROLEeProvider`].
    pub fn new(rot_sender: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            rot_sender,
            role_core: ROLEeCoreProvider::default(),
        }
    }
}

#[async_trait]
impl<const N: usize, T, F: Field> RandomOLEeProvide<F> for ROLEeProvider<N, T, F>
where
    T: RandomOTSender<[[u8; N]; 2]> + Send,
    Self: Send,
{
    async fn provide_random(&mut self, count: usize) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let ti01 = self
            .rot_sender
            .send_random(count * F::BIT_SIZE as usize)
            .await?;

        let (ck, ek) = self.role_core.sample_c_and_e(count);
        let (ui, t0i): (Vec<F>, Vec<F>) = self.role_core.create_correlation(&ti01, &ck)?;

        sink.send(ROLEeMessage::RandomProviderMsg(ui, ek.clone()))
            .await?;

        let dk: Vec<F> = stream
            .expect_next()
            .await?
            .try_into_random_evaluator_msg()?;

        let (ak, xk) = self.role_core.generate_output(&t0i, &ck, &dk, &ek)?;

        Ok((ak, xk))
    }
}
