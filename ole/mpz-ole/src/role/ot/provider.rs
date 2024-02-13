use std::marker::PhantomData;

use crate::{
    msg::ROLEeMessage,
    role::ot::{into_rot_sink, into_rot_stream},
    Check, OLEError, RandomOLEeProvide,
};
use async_trait::async_trait;
use futures::SinkExt;
use itybity::IntoBitIterator;
use mpz_core::ProtocolMessage;
use mpz_ot::RandomOTSender;
use mpz_share_conversion_core::Field;
use rand::thread_rng;
use utils_aio::{
    sink::IoSink,
    stream::{ExpectStreamExt, IoStream},
};

/// A provider for ROLEe.
pub struct ROLEeProvider<const N: usize, T: RandomOTSender<[[u8; N]; 2]>, F> {
    rot_sender: T,
    field: PhantomData<F>,
}

impl<const N: usize, T: RandomOTSender<[[u8; N]; 2]>, F: Field> ROLEeProvider<N, T, F> {
    /// Create a new [`ROLEeProvider`].
    pub fn new(rot_sender: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            rot_sender,
            field: PhantomData,
        }
    }
}

impl<const N: usize, T: RandomOTSender<[[u8; N]; 2]>, F: Field> ProtocolMessage
    for ROLEeProvider<N, T, F>
{
    type Msg = ROLEeMessage<T::Msg, F>;
}

#[async_trait]
impl<const N: usize, T, F: Field> RandomOLEeProvide<F> for ROLEeProvider<N, T, F>
where
    T: RandomOTSender<[[u8; N]; 2]> + Send + ProtocolMessage,
    Self: Send,
{
    async fn provide_random<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        count: usize,
    ) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let (ck, ek): (Vec<F>, Vec<F>) = {
            let mut rng = thread_rng();

            (
                (0..count).map(|_| F::rand(&mut rng)).collect(),
                (0..count).map(|_| F::rand(&mut rng)).collect(),
            )
        };

        let ti01 = self
            .rot_sender
            .send_random(
                &mut into_rot_sink(sink),
                &mut into_rot_stream(stream),
                count * F::BIT_SIZE as usize,
            )
            .await?;

        let (ui, t0i): (Vec<F>, Vec<F>) = ti01
            .chunks(F::BIT_SIZE as usize)
            .zip(ck.iter().copied())
            .flat_map(|(chunk, c)| {
                chunk.iter().map(move |[t0, t1]| {
                    let t0 = F::from_lsb0_iter(t0.into_iter_lsb0());
                    let t1 = F::from_lsb0_iter(t1.into_iter_lsb0());
                    (t0 + -t1 + c, t0)
                })
            })
            .unzip();

        sink.send(ROLEeMessage::RandomProviderMsg(ui, ek.clone()))
            .await?;

        let dk: Vec<F> = stream
            .expect_next()
            .await?
            .try_into_random_evaluator_msg()
            .map_err(|err| OLEError::ROLEeError(err.to_string()))?;

        let t0k: Vec<F> = t0i
            .chunks(F::BIT_SIZE as usize)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(F::zero(), |acc, (k, &el)| acc + F::two_pow(k as u32) * el)
            })
            .collect();

        let ak: Vec<F> = ck.iter().zip(dk).map(|(&c, d)| c + d).collect();
        let xk: Vec<F> = t0k
            .iter()
            .zip(ak.iter().copied())
            .zip(ek)
            .map(|((&t, a), k)| t + -(a * k))
            .collect();

        Ok((ak, xk))
    }
}
