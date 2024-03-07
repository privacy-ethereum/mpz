//! Provides an implementation of OLEe based on ROLEe.

mod evaluator;
mod provider;

pub use evaluator::OLEeEvaluator;
pub use provider::OLEeProvider;

#[cfg(test)]
mod tests {
    use super::{OLEeEvaluator, OLEeProvider};
    use crate::ideal::role::ideal_role_pair;
    use crate::{OLEeEvaluate, OLEeProvide};
    use mpz_common::executor::test_st_executor;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_ole() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (role_provider, role_evaluator) = ideal_role_pair::<P256>();

        let (mut ctx_provider, mut ctx_evaluator) = test_st_executor(10);

        let mut ole_provider = OLEeProvider::<32, _, P256>::new(role_provider);
        let mut ole_evaluator = OLEeEvaluator::<32, _, P256>::new(role_evaluator);

        let ak: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let bk: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (provider_res, evaluator_res) = tokio::join!(
            ole_provider.provide(&mut ctx_provider, ak.clone()),
            ole_evaluator.evaluate(&mut ctx_evaluator, bk.clone())
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
