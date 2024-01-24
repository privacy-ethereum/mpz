use std::marker::PhantomData;

use crate::{Check, OLEError, RandomOLEeEvaluate};
use async_trait::async_trait;
use mpz_core::ProtocolMessage;
use mpz_ot::RandomOTReceiver;
use mpz_share_conversion_core::Field;
use rand::rngs::ThreadRng;
use utils_aio::{sink::IoSink, stream::IoStream};

/// An evaluator for ROLEe.
pub struct ROLEeEvaluator<const N: usize, T: RandomOTReceiver<bool, [u8; N]>, F: Field> {
    rot_receiver: T,
    rng: ThreadRng,
    field: PhantomData<F>,
}

impl<const N: usize, T: RandomOTReceiver<bool, [u8; N]>, F: Field> ProtocolMessage
    for ROLEeEvaluator<N, T, F>
{
    type Msg = ();
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
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        todo!()
    }
}
