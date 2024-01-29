//! Provides implementations of ROLEe protocols based on oblivious transfer.

mod evaluator;
mod provider;

pub use evaluator::ROLEeEvaluator;
pub use provider::ROLEeProvider;

use crate::msg::ROLEeMessage;
use futures::{SinkExt, StreamExt};
use mpz_share_conversion_core::Field;
use utils_aio::{sink::IoSink, stream::IoStream};

/// Converts a sink of random OLE messages into a sink of random OT messages.
fn into_rot_sink<'a, Si: IoSink<ROLEeMessage<T, F>> + Send + Unpin, T: Send + 'a, F: Field>(
    sink: &'a mut Si,
) -> impl IoSink<T> + Send + Unpin + 'a {
    Box::pin(SinkExt::with(sink, |msg| async move {
        Ok(ROLEeMessage::RandomOTMessage(msg))
    }))
}

/// Converts a stream of random OLE messages into a stream of random OT messages.
fn into_rot_stream<'a, St: IoStream<ROLEeMessage<T, F>> + Send + Unpin, T: Send + 'a, F: Field>(
    stream: &'a mut St,
) -> impl IoStream<T> + Send + Unpin + 'a {
    StreamExt::map(stream, |msg| match msg {
        Ok(msg) => msg.try_into_random_ot_message().map_err(From::from),
        Err(err) => Err(err),
    })
}

#[cfg(test)]
mod tests {
    use super::{ROLEeEvaluator, ROLEeProvider};
    use crate::{RandomOLEeEvaluate, RandomOLEeProvide};
    use futures::StreamExt;
    use mpz_ot::ideal::ideal_random_ot_pair;
    use mpz_share_conversion_core::fields::p256::P256;
    use utils_aio::duplex::MemoryDuplex;

    #[tokio::test]
    async fn test_role() {
        let (sender_channel, receiver_channel) = MemoryDuplex::new();

        let (mut provider_sink, mut provider_stream) = sender_channel.split();
        let (mut evaluator_sink, mut evaluator_stream) = receiver_channel.split();

        let (rot_sender, rot_receiver) = ideal_random_ot_pair::<[u8; 256]>([0; 32]);

        let mut role_provider = ROLEeProvider::<256, _, P256>::new(rot_sender);
        let mut role_evaluator = ROLEeEvaluator::<256, _, P256>::new(rot_receiver);

        let (provider_res, evaluator_res) = tokio::join!(
            role_provider.provide_random(&mut provider_sink, &mut provider_stream, 16),
            role_evaluator.evaluate_random(&mut evaluator_sink, &mut evaluator_stream, 16)
        );

        let (ak, xk) = provider_res.unwrap();
        let (bk, yk) = evaluator_res.unwrap();

        ak.iter()
            .zip(bk)
            .zip(xk)
            .zip(yk)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
