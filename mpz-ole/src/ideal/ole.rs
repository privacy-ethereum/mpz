//! This module contains an ideal OLE implementation.

use crate::{OLEError, OLEeEvaluate, OLEeProvide};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use mpz_core::ProtocolMessage;
use mpz_share_conversion_core::Field;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::marker::PhantomData;
use utils_aio::{sink::IoSink, stream::IoStream};

/// Returns an ideal OLE pair
pub fn ideal_ole_pair<F: Field>() -> (IdealOLEProvider<F>, IdealOLEEvaluator<F>) {
    let (sender, receiver) = mpsc::channel(10);
    let rng = ChaCha12Rng::from_seed([1_u8; 32]);

    let provider = IdealOLEProvider {
        phantom: PhantomData,
        channel: sender,
        rng,
    };

    let evaluator = IdealOLEEvaluator {
        phantom: PhantomData,
        channel: receiver,
    };

    (provider, evaluator)
}

/// An ideal OLEProvider for field elements
pub struct IdealOLEProvider<F: Field> {
    phantom: PhantomData<F>,
    rng: ChaCha12Rng,
    channel: mpsc::Sender<(Vec<F>, Vec<F>)>,
}

impl<F: Field> ProtocolMessage for IdealOLEProvider<F> {
    type Msg = ();
}

/// An ideal OLEEvaluator for field elements
pub struct IdealOLEEvaluator<F: Field> {
    phantom: PhantomData<F>,
    channel: mpsc::Receiver<(Vec<F>, Vec<F>)>,
}

impl<F: Field> ProtocolMessage for IdealOLEEvaluator<F> {
    type Msg = ();
}

#[async_trait]
impl<F: Field> OLEeProvide<F> for IdealOLEProvider<F> {
    async fn provide<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        _sink: &mut Si,
        _stream: &mut St,
        factors: Vec<F>,
    ) -> Result<Vec<F>, OLEError> {
        let summands: Vec<F> = (0..factors.len()).map(|_| F::rand(&mut self.rng)).collect();
        self.channel
            .try_send((factors.clone(), summands.clone()))
            .expect("DummySender should be able to send");

        Ok(summands)
    }
}

#[async_trait]
impl<F: Field> OLEeEvaluate<F> for IdealOLEEvaluator<F> {
    async fn evaluate<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        _sink: &mut Si,
        _stream: &mut St,
        input: Vec<F>,
    ) -> Result<Vec<F>, OLEError> {
        let (factors, summands) = self
            .channel
            .next()
            .await
            .expect("DummySender should send a value");

        let output: Vec<F> = input
            .iter()
            .zip(factors.iter().copied())
            .zip(summands)
            .map(|((&a, b), x)| a * b + x)
            .collect();

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::{ideal::ole::ideal_ole_pair, OLEeEvaluate, OLEeProvide};
    use futures::StreamExt;
    use mpz_share_conversion_core::fields::{p256::P256, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use utils_aio::duplex::MemoryDuplex;

    #[tokio::test]
    async fn test_ideal_ole() {
        let count = 16;
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);

        let inputs: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let factors: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (send_channel, recv_channel) = MemoryDuplex::<()>::new();

        let (mut provider_sink, mut provider_stream) = send_channel.split();
        let (mut evaluator_sink, mut evaluator_stream) = recv_channel.split();

        let (mut provider, mut evaluator) = ideal_ole_pair::<P256>();

        let summands = provider
            .provide(&mut provider_sink, &mut provider_stream, factors.clone())
            .await
            .unwrap();
        let outputs = evaluator
            .evaluate(&mut evaluator_sink, &mut evaluator_stream, inputs.clone())
            .await
            .unwrap();

        inputs
            .iter()
            .zip(factors)
            .zip(summands)
            .zip(outputs)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
