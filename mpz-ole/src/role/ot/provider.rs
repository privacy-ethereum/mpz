use crate::{Check, OLEError, RandomOLEeProvide};
use async_trait::async_trait;
use mpz_core::ProtocolMessage;
use mpz_ot::RandomOTSender;
use mpz_share_conversion_core::Field;
use utils_aio::{sink::IoSink, stream::IoStream};

/// A provider for ROLEe.
pub struct ROLEeProvider<const N: usize, T: RandomOTSender<[u8; N]>> {
    rot_sender: T,
}

impl<const N: usize, T: RandomOTSender<[u8; N]>> ProtocolMessage for ROLEeProvider<N, T> {
    type Msg = ();
}

#[async_trait]
impl<const N: usize, T> RandomOLEeProvide<N> for ROLEeProvider<N, T>
where
    T: RandomOTSender<[u8; N]> + Send,
{
    async fn provide_random<
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
