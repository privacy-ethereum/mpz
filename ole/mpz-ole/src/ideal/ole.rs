//! This module contains an ideal OLE implementation.

use crate::{OLEError, OLEeEvaluate, OLEeProvide};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use mpz_core::ProtocolMessage;
use mpz_fields::Field;
use rand::thread_rng;
use std::marker::PhantomData;

/// Returns an ideal OLE pair.
pub fn ideal_ole_pair<F: Field>() -> (IdealOLEProvider<F>, IdealOLEEvaluator<F>) {
    let (sender, receiver) = mpsc::channel(10);

    let provider = IdealOLEProvider {
        phantom: PhantomData,
        channel: sender,
    };

    let evaluator = IdealOLEEvaluator {
        phantom: PhantomData,
        channel: receiver,
    };

    (provider, evaluator)
}

/// An ideal OLE Provider.
pub struct IdealOLEProvider<F: Field> {
    phantom: PhantomData<F>,
    channel: mpsc::Sender<(Vec<F>, Vec<F>)>,
}

impl<F: Field> ProtocolMessage for IdealOLEProvider<F> {
    type Msg = ();
}

/// An ideal OLE Evaluator.
pub struct IdealOLEEvaluator<F: Field> {
    phantom: PhantomData<F>,
    channel: mpsc::Receiver<(Vec<F>, Vec<F>)>,
}

impl<F: Field> ProtocolMessage for IdealOLEEvaluator<F> {
    type Msg = ();
}

#[async_trait]
impl<F: Field> OLEeProvide<F> for IdealOLEProvider<F> {
    async fn provide(&mut self, factors: Vec<F>) -> Result<Vec<F>, OLEError> {
        let mut rng = thread_rng();
        let offsets: Vec<F> = (0..factors.len()).map(|_| F::rand(&mut rng)).collect();

        self.channel
            .try_send((factors.clone(), offsets.clone()))
            .expect("DummySender should be able to send");

        Ok(offsets)
    }
}

#[async_trait]
impl<F: Field> OLEeEvaluate<F> for IdealOLEEvaluator<F> {
    async fn evaluate(&mut self, input: Vec<F>) -> Result<Vec<F>, OLEError> {
        let (factors, offsets) = self
            .channel
            .next()
            .await
            .expect("DummySender should send a value");

        let output: Vec<F> = input
            .iter()
            .zip(factors)
            .zip(offsets)
            .map(|((&a, b), x)| a * b + x)
            .collect();

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::{ideal::ole::ideal_ole_pair, OLEeEvaluate, OLEeProvide};
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_ideal_ole() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let inputs: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let factors: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (mut provider, mut evaluator) = ideal_ole_pair::<P256>();

        let offsets = provider.provide(factors.clone()).await.unwrap();
        let outputs = evaluator.evaluate(inputs.clone()).await.unwrap();

        inputs
            .iter()
            .zip(factors)
            .zip(offsets)
            .zip(outputs)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
