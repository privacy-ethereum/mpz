//! Ideal OLE implementation.

use crate::{OLEError, OLEReceiver, OLESender};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use mpz_common::Context;
use mpz_fields::Field;
use rand::thread_rng;

/// Returns an OLE sender and receiver pair.
pub fn ideal_ole<F: Field>() -> (IdealOLESender<F>, IdealOLEReceiver<F>) {
    let (sender, receiver) = mpsc::channel(10);

    let ole_sender = IdealOLESender { channel: sender };

    let ole_receiver = IdealOLEReceiver { channel: receiver };

    (ole_sender, ole_receiver)
}

/// An ideal OLE Sender.
pub struct IdealOLESender<F: Field> {
    channel: mpsc::Sender<(Vec<F>, Vec<F>)>,
}

/// An ideal OLE Receiver.
pub struct IdealOLEReceiver<F: Field> {
    channel: mpsc::Receiver<(Vec<F>, Vec<F>)>,
}

#[async_trait]
impl<F: Field, C: Context> OLESender<C, F> for IdealOLESender<F> {
    async fn send(&mut self, _ctx: &mut C, a_k: Vec<F>) -> Result<Vec<F>, OLEError> {
        let mut rng = thread_rng();
        let x_k: Vec<F> = (0..a_k.len()).map(|_| F::rand(&mut rng)).collect();

        self.channel
            .try_send((a_k, x_k.clone()))
            .expect("DummySender should be able to send");

        Ok(x_k)
    }
}

#[async_trait]
impl<F: Field, C: Context> OLEReceiver<C, F> for IdealOLEReceiver<F> {
    async fn receive(&mut self, _ctx: &mut C, b_k: Vec<F>) -> Result<Vec<F>, OLEError> {
        let (a_k, x_k) = self
            .channel
            .next()
            .await
            .expect("DummySender should send a value");

        let y_k: Vec<F> = a_k
            .iter()
            .zip(b_k.iter())
            .zip(x_k)
            .map(|((&a, &b), x)| a * b + x)
            .collect();

        Ok(y_k)
    }
}

#[cfg(test)]
mod tests {
    use crate::{ideal::ideal_ole, OLEReceiver, OLESender};
    use mpz_common::executor::test_st_executor;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_ideal_ole() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let a_k: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let b_k: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(10);

        let (mut sender, mut receiver) = ideal_ole::<P256>();
        let x_k = sender.send(&mut ctx_sender, a_k.clone()).await.unwrap();
        let y_k = receiver
            .receive(&mut ctx_receiver, b_k.clone())
            .await
            .unwrap();

        assert_eq!(x_k.len(), count);
        assert_eq!(y_k.len(), count);
        a_k.iter()
            .zip(b_k)
            .zip(x_k)
            .zip(y_k)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
