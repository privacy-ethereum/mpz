use std::marker::PhantomData;

use crate::{Check, OLEError, OLEeProvide, RandomOLEeProvide};
use async_trait::async_trait;
use mpz_core::ProtocolMessage;
use mpz_share_conversion_core::Field;
use utils_aio::{sink::IoSink, stream::IoStream};

/// A provider for various OLE constructions.
pub struct OLEeProvider<const N: usize, T: RandomOLEeProvide<F>, F: Field> {
    role_provider_sender: T,
    field: PhantomData<F>,
}

impl<const N: usize, T: RandomOLEeProvide<F>, F: Field> ProtocolMessage for OLEeProvider<N, T, F> {
    type Msg = ();
}

#[async_trait]
impl<const N: usize, T, F: Field> OLEeProvide<F> for OLEeProvider<N, T, F>
where
    T: RandomOLEeProvide<F> + Send,
{
    async fn provide<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        sink: &mut Si,
        stream: &mut St,
        factors: Vec<F>,
        summands: Vec<F>,
    ) -> Result<(), OLEError> {
        // Check that the right N is used depending on the needed bit size of the field.
        let _: () = Check::<N, F>::IS_BITSIZE_CORRECT;

        todo!()
    }
}
