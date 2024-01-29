use std::marker::PhantomData;

use crate::{Check, OLEError, OLEeEvaluate, RandomOLEeEvaluate};
use async_trait::async_trait;
use mpz_core::ProtocolMessage;
use mpz_share_conversion_core::Field;
use utils_aio::{sink::IoSink, stream::IoStream};

/// An evaluator for OLEe.
pub struct OLEeEvaluator<const N: usize, T: RandomOLEeEvaluate<F>, F: Field> {
    role_evaluator: T,
    field: PhantomData<F>,
}

impl<const N: usize, T: RandomOLEeEvaluate<F>, F: Field> ProtocolMessage
    for OLEeEvaluator<N, T, F>
{
    type Msg = ();
}

#[async_trait]
impl<const N: usize, T, F: Field> OLEeEvaluate<F> for OLEeEvaluator<N, T, F>
where
    T: RandomOLEeEvaluate<F> + Send,
{
    async fn evaluate<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, OLEError> {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        todo!()
    }
}
