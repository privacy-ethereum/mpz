//! Provides an implementation of OLEe based on ROLEe.

mod evaluator;
mod provider;

pub use evaluator::OLEeEvaluator;
pub use provider::OLEeProvider;

#[cfg(test)]
mod tests {
    use super::{OLEeEvaluator, OLEeProvider};
    use crate::{ideal::role::ideal_role_pair, OLEeEvaluate, OLEeProvide};
    use mpz_core::{prg::Prg, Block};
    use mpz_share_conversion_core::fields::{p256::P256, UniformRand};
    use rand::SeedableRng;
    use utils_aio::duplex::MemoryDuplex;

    #[tokio::test]
    async fn test_ole() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (sender_channel, receiver_channel) = MemoryDuplex::new();

        let (role_provider, role_evaluator) = ideal_role_pair::<P256>();

        let mut ole_provider = OLEeProvider::<32, _, P256, _>::new(sender_channel, role_provider);
        let mut ole_evaluator =
            OLEeEvaluator::<32, _, P256, _>::new(receiver_channel, role_evaluator);

        let ak: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let bk: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (provider_res, evaluator_res) = tokio::join!(
            ole_provider.provide(ak.clone()),
            ole_evaluator.evaluate(bk.clone())
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
