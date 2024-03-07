//! This module contains an ideal ROLE implementation.

use crate::{OLEError, RandomOLEeEvaluate, RandomOLEeProvide};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use mpz_core::ProtocolMessage;
use mpz_fields::Field;
use rand::thread_rng;
use std::marker::PhantomData;

/// Returns an ideal ROLE pair.
pub fn ideal_role_pair<F: Field>() -> (IdealROLEProvider<F>, IdealROLEEvaluator<F>) {
    let (sender, receiver) = mpsc::channel(10);

    let provider = IdealROLEProvider {
        phantom: PhantomData,
        channel: sender,
    };

    let evaluator = IdealROLEEvaluator {
        phantom: PhantomData,
        channel: receiver,
    };

    (provider, evaluator)
}

/// An ideal ROLE Provider.
pub struct IdealROLEProvider<F: Field> {
    phantom: PhantomData<F>,
    channel: mpsc::Sender<(Vec<F>, Vec<F>)>,
}

impl<F: Field> ProtocolMessage for IdealROLEProvider<F> {
    type Msg = ();
}

/// An ideal ROLE Evaluator.
pub struct IdealROLEEvaluator<F: Field> {
    phantom: PhantomData<F>,
    channel: mpsc::Receiver<(Vec<F>, Vec<F>)>,
}

impl<F: Field> ProtocolMessage for IdealROLEEvaluator<F> {
    type Msg = ();
}

#[async_trait]
impl<F: Field> RandomOLEeProvide<F> for IdealROLEProvider<F> {
    async fn provide_random(&mut self, count: usize) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let mut rng = thread_rng();

        let ak: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();
        let xk: Vec<F> = (0..count).map(|_| F::rand(&mut rng)).collect();

        self.channel
            .try_send((ak.clone(), xk.clone()))
            .expect("DummySender should be able to send");

        Ok((ak, xk))
    }
}

#[async_trait]
impl<F: Field> RandomOLEeEvaluate<F> for IdealROLEEvaluator<F> {
    async fn evaluate_random(&mut self, count: usize) -> Result<(Vec<F>, Vec<F>), OLEError> {
        let bk: Vec<F> = {
            let mut rng = thread_rng();
            (0..count).map(|_| F::rand(&mut rng)).collect()
        };

        let (ak, xk) = self
            .channel
            .next()
            .await
            .expect("DummySender should send a value");

        let yk: Vec<F> = ak
            .iter()
            .zip(bk.iter())
            .zip(xk)
            .map(|((&a, &b), x)| a * b + x)
            .collect();

        Ok((bk, yk))
    }
}

#[cfg(test)]
mod tests {
    use crate::{ideal::role::ideal_role_pair, RandomOLEeEvaluate, RandomOLEeProvide};
    use mpz_fields::p256::P256;

    #[tokio::test]
    async fn test_ideal_role() {
        let count = 12;

        let (mut provider, mut evaluator) = ideal_role_pair::<P256>();

        let (ak, xk) = provider.provide_random(count).await.unwrap();

        let (bk, yk) = evaluator.evaluate_random(count).await.unwrap();

        ak.iter()
            .zip(bk)
            .zip(xk)
            .zip(yk)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
