use crate::{Check, OLEError, RandomOLEeEvaluate};
use async_trait::async_trait;
use mpz_core::ProtocolMessage;
use mpz_ot::RandomOTReceiver;
use mpz_share_conversion_core::Field;
use utils_aio::{sink::IoSink, stream::IoStream};

/// An evaluator for ROLEe.
pub struct ROLEeEvaluator<const N: usize, T: RandomOTReceiver<bool, [u8; N]>> {
    rot_receiver: T,
}

impl<const N: usize, T: RandomOTReceiver<bool, [u8; N]>> ProtocolMessage for ROLEeEvaluator<N, T> {
    type Msg = ();
}

#[async_trait]
impl<const N: usize, T> RandomOLEeEvaluate<N> for ROLEeEvaluator<N, T>
where
    T: RandomOTReceiver<bool, [u8; N]> + Send,
{
    async fn evaluate_random<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
        F: Field,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
    ) -> Result<(Vec<F>, Vec<F>), OLEError> {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        todo!()
    }
}
