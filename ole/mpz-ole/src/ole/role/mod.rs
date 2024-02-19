//! Provides implementations of OLE with errors (OLEe) based on ROLEe.

mod evaluator;
mod provider;

pub use evaluator::OLEeEvaluator;
pub use provider::OLEeProvider;

use futures::{SinkExt, StreamExt};
use mpz_share_conversion_core::Field;
use utils_aio::{sink::IoSink, stream::IoStream};

use crate::msg::OLEeMessage;

/// Converts a sink of OLEe messages into a sink of ROLEe messsages.
fn into_role_sink<'a, Si: IoSink<OLEeMessage<T, F>> + Send + Unpin, T: Send + 'a, F: Field>(
    sink: &'a mut Si,
) -> impl IoSink<T> + Send + Unpin + 'a {
    Box::pin(SinkExt::with(sink, |msg| async move {
        Ok(OLEeMessage::ROLEeMessage(msg))
    }))
}

/// Converts a stream of OLEe messages into a stream of ROLEe messsages.
fn into_role_stream<'a, St: IoStream<OLEeMessage<T, F>> + Send + Unpin, T: Send + 'a, F: Field>(
    stream: &'a mut St,
) -> impl IoStream<T> + Send + Unpin + 'a {
    StreamExt::map(stream, |msg| match msg {
        Ok(msg) => msg.try_into_rol_ee_message().map_err(From::from),
        Err(err) => Err(err),
    })
}

#[cfg(test)]
mod tests {
    use super::{OLEeEvaluator, OLEeProvider};
    use crate::{ideal::role::ideal_role_pair, OLEeEvaluate, OLEeProvide};
    use futures::StreamExt;
    use mpz_share_conversion_core::fields::{p256::P256, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use utils_aio::duplex::MemoryDuplex;

    #[tokio::test]
    async fn test_ole() {
        let count = 16;
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        let (sender_channel, receiver_channel) = MemoryDuplex::new();

        let (mut provider_sink, mut provider_stream) = sender_channel.split();
        let (mut evaluator_sink, mut evaluator_stream) = receiver_channel.split();

        let (role_provider, role_evaluator) = ideal_role_pair::<P256>();

        let mut ole_provider = OLEeProvider::<32, _, P256>::new(role_provider);
        let mut ole_evaluator = OLEeEvaluator::<32, _, P256>::new(role_evaluator);

        let ak: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let bk: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (provider_res, evaluator_res) = tokio::join!(
            ole_provider.provide(&mut provider_sink, &mut provider_stream, ak.clone()),
            ole_evaluator.evaluate(&mut evaluator_sink, &mut evaluator_stream, bk.clone())
        );

        let xk = provider_res.unwrap();
        let yk = evaluator_res.unwrap();

        ak.iter()
            .zip(bk)
            .zip(xk)
            .zip(yk)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
