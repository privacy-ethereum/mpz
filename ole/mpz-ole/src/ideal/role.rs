//! This module contains an ideal ROLE implementation.

use crate::{OLEError, RandomOLEeEvaluate, RandomOLEeProvide};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use mpz_core::ProtocolMessage;
use mpz_share_conversion_core::Field;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::marker::PhantomData;
use utils_aio::{sink::IoSink, stream::IoStream};

/// Returns an ideal ROLE pair
pub fn ideal_role_pair<F: Field>() -> (IdealROLEProvider<F>, IdealROLEEvaluator<F>) {
    let (sender, receiver) = mpsc::channel(10);

    let provider = IdealROLEProvider {
        phantom: PhantomData,
        rng: ChaCha12Rng::from_seed([1_u8; 32]),
        channel: sender,
    };

    let evaluator = IdealROLEEvaluator {
        phantom: PhantomData,
        rng: ChaCha12Rng::from_seed([2_u8; 32]),
        channel: receiver,
    };

    (provider, evaluator)
}

/// An ideal ROLEProvider for field elements
pub struct IdealROLEProvider<F: Field> {
    phantom: PhantomData<F>,
    rng: ChaCha12Rng,
    channel: mpsc::Sender<(Vec<F>, Vec<F>)>,
}

impl<F: Field> ProtocolMessage for IdealROLEProvider<F> {
    type Msg = ();
}

/// An ideal ROLEEvaluator for field elements
pub struct IdealROLEEvaluator<F: Field> {
    phantom: PhantomData<F>,
    rng: ChaCha12Rng,
    channel: mpsc::Receiver<(Vec<F>, Vec<F>)>,
}

impl<F: Field> ProtocolMessage for IdealROLEEvaluator<F> {
    type Msg = ();
}

#[async_trait]
impl<F: Field> RandomOLEeProvide<F> for IdealROLEProvider<F> {
    async fn provide_random<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        _sink: &mut Si,
        _stream: &mut St,
        count: usize,
    ) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let ak: Vec<F> = (0..count).map(|_| F::rand(&mut self.rng)).collect();
        let xk: Vec<F> = (0..count).map(|_| F::rand(&mut self.rng)).collect();

        self.channel
            .try_send((ak.clone(), xk.clone()))
            .expect("DummySender should be able to send");

        Ok((ak, xk))
    }
}

#[async_trait]
impl<F: Field> RandomOLEeEvaluate<F> for IdealROLEEvaluator<F> {
    async fn evaluate_random<
        Si: IoSink<Self::Msg> + Send + Unpin,
        St: IoStream<Self::Msg> + Send + Unpin,
    >(
        &mut self,
        _sink: &mut Si,
        _stream: &mut St,
        count: usize,
    ) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let bk: Vec<F> = (0..count).map(|_| F::rand(&mut self.rng)).collect();

        let (ak, xk) = self
            .channel
            .next()
            .await
            .expect("DummySender should send a value");

        let yk: Vec<F> = ak
            .iter()
            .zip(bk.iter().copied())
            .zip(xk)
            .map(|((&a, b), x)| a * b + x)
            .collect();

        Ok((bk, yk))
    }
}

#[cfg(test)]
mod tests {
    use crate::{ideal::role::ideal_role_pair, RandomOLEeEvaluate, RandomOLEeProvide};
    use futures::StreamExt;
    use mpz_share_conversion_core::fields::p256::P256;
    use utils_aio::duplex::MemoryDuplex;

    #[tokio::test]
    async fn test_ideal_role() {
        let count = 16;

        let (send_channel, recv_channel) = MemoryDuplex::<()>::new();

        let (mut provider_sink, mut provider_stream) = send_channel.split();
        let (mut evaluator_sink, mut evaluator_stream) = recv_channel.split();

        let (mut provider, mut evaluator) = ideal_role_pair::<P256>();

        let (ak, xk) = provider
            .provide_random(&mut provider_sink, &mut provider_stream, count)
            .await
            .unwrap();
        let (bk, yk) = evaluator
            .evaluate_random(&mut evaluator_sink, &mut evaluator_stream, count)
            .await
            .unwrap();

        ak.iter()
            .zip(bk)
            .zip(xk)
            .zip(yk)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
