use std::marker::PhantomData;

use crate::{
    msg::ROLEeMessage,
    role::ot::{into_rot_sink, into_rot_stream},
    Check, OLEError, RandomOLEeEvaluate,
};
use async_trait::async_trait;
use futures::SinkExt;
use itybity::IntoBitIterator;
use mpz_core::ProtocolMessage;
use mpz_ot::RandomOTReceiver;
use mpz_share_conversion_core::Field;
use rand::thread_rng;
use utils_aio::{
    sink::IoSink,
    stream::{ExpectStreamExt, IoStream},
};

/// An evaluator for ROLEe.
pub struct ROLEeEvaluator<const N: usize, T: RandomOTReceiver<bool, [u8; N]>, F: Field> {
    rot_receiver: T,
    field: PhantomData<F>,
}

impl<const N: usize, T: RandomOTReceiver<bool, [u8; N]>, F: Field> ROLEeEvaluator<N, T, F> {
    /// Create a new [`ROLEeEvaluator`].
    pub fn new(rot_receiver: T) -> Self {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        Self {
            rot_receiver,
            field: PhantomData,
        }
    }
}

impl<const N: usize, T: RandomOTReceiver<bool, [u8; N]>, F: Field> ProtocolMessage
    for ROLEeEvaluator<N, T, F>
{
    type Msg = ROLEeMessage<T::Msg, F>;
}

#[async_trait]
impl<const N: usize, T, F: Field> RandomOLEeEvaluate<F> for ROLEeEvaluator<N, T, F>
where
    T: RandomOTReceiver<bool, [u8; N]> + Send,
    Self: Send,
{
    async fn evaluate_random<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        count: usize,
    ) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let dk: Vec<F> = {
            let mut rng = thread_rng();
            (0..count).map(|_| F::rand(&mut rng)).collect()
        };

        let (fi, tfi): (Vec<bool>, Vec<[u8; N]>) = self
            .rot_receiver
            .receive_random(
                &mut into_rot_sink(sink),
                &mut into_rot_stream(stream),
                count * F::BIT_SIZE as usize,
            )
            .await?;

        let fk: Vec<F> = fi
            .chunks(F::BIT_SIZE as usize)
            .map(|f| F::from_lsb0_iter(f.into_iter_lsb0()))
            .collect();

        let (ui, ek): (Vec<F>, Vec<F>) = stream
            .expect_next()
            .await?
            .try_into_random_provider_msg()
            .map_err(|err| OLEError::WrongMessage(err.to_string()))?;

        sink.send(ROLEeMessage::RandomEvaluatorMsg(dk.clone()))
            .await?;

        let bk: Vec<F> = fk.iter().zip(ek).map(|(&f, e)| f + e).collect();

        let yk: Vec<F> = fi
            .chunks(F::BIT_SIZE as usize)
            .zip(tfi.chunks(F::BIT_SIZE as usize))
            .zip(ui.chunks(F::BIT_SIZE as usize))
            .zip(dk)
            .map(|(((f, t), u), d)| {
                f.iter()
                    .zip(t)
                    .zip(u)
                    .enumerate()
                    .fold(F::zero(), |acc, (i, ((&f, t), &u))| {
                        let f = if f { F::one() } else { F::zero() };
                        acc + F::two_pow(i as u32)
                            * (f * (u + d) + F::from_lsb0_iter(t.into_iter_lsb0()))
                    })
            })
            .collect();

        Ok((bk, yk))
    }
}
