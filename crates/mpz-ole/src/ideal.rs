//! Ideal OLE implementation.

use crate::{OLEError, OLEReceiver, OLESender};
use async_trait::async_trait;
use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Context,
};
use mpz_fields::Field;
use rand::thread_rng;

/// Ideal OLESender.
pub struct IdealOLESender(Alice<()>);

/// Ideal OLEReceiver.
pub struct IdealOLEReceiver(Bob<()>);

/// Returns an OLE sender and receiver pair.
pub fn ideal_ole() -> (IdealOLESender, IdealOLEReceiver) {
    let (alice, bob) = ideal_f2p(());

    (IdealOLESender(alice), IdealOLEReceiver(bob))
}

fn ole<F: Field>(_: &mut (), alice_input: Vec<F>, bob_input: Vec<F>) -> (Vec<F>, Vec<F>) {
    let mut rng = thread_rng();
    let alice_output: Vec<F> = (0..alice_input.len()).map(|_| F::rand(&mut rng)).collect();

    let bob_output: Vec<F> = alice_input
        .iter()
        .zip(bob_input.iter())
        .zip(alice_output.iter().copied())
        .map(|((&a, &b), x)| a * b + x)
        .collect();

    (alice_output, bob_output)
}

#[async_trait]
impl<F: Field, Ctx: Context> OLESender<Ctx, F> for IdealOLESender {
    async fn send(&mut self, ctx: &mut Ctx, a_k: Vec<F>) -> Result<Vec<F>, OLEError> {
        Ok(self.0.call(ctx, a_k, ole).await)
    }
}

#[async_trait]
impl<F: Field, Ctx: Context> OLEReceiver<Ctx, F> for IdealOLEReceiver {
    async fn receive(&mut self, ctx: &mut Ctx, b_k: Vec<F>) -> Result<Vec<F>, OLEError> {
        Ok(self.0.call(ctx, b_k, ole).await)
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

        let (mut sender, mut receiver) = ideal_ole();

        let (x_k, y_k) = tokio::try_join!(
            sender.send(&mut ctx_sender, a_k.clone()),
            receiver.receive(&mut ctx_receiver, b_k.clone())
        )
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
