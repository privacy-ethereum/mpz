//! Provides implementations of OLEe protocols based on ROLEe.

mod evaluator;
mod provider;

pub use evaluator::OLEeEvaluator;
pub use provider::OLEeProvider;

#[cfg(test)]
mod tests {
    use super::{OLEeEvaluator, OLEeProvider};
    use crate::ideal::ROLEFunctionality;
    use mpz_share_conversion_core::fields::{p256::P256, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_ole_role_core() {
        let count = 12;
        let mut rng = ChaCha12Rng::from_seed([0_u8; 32]);
        let mut role: ROLEFunctionality<P256> = ROLEFunctionality::default();

        let provider: OLEeProvider<P256> = OLEeProvider::default();
        let evaluator: OLEeEvaluator<P256> = OLEeEvaluator::default();

        let (ak_dash, xk_dash) = role.provide_random(count);
        let (bk_dash, yk_dash) = role.evaluate_random(count);

        let ak: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let bk: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let uk = provider.create_mask(&ak_dash, &ak).unwrap();
        let vk = evaluator.create_mask(&bk_dash, &bk).unwrap();

        let xk = provider.generate_output(&ak_dash, &xk_dash, &vk).unwrap();
        let yk = evaluator.generate_output(&bk, &yk_dash, &uk).unwrap();

        yk.iter()
            .zip(xk.iter())
            .zip(ak.iter())
            .zip(bk.iter())
            .for_each(|(((&y, &x), &a), &b)| assert_eq!(y, a * b + x));
    }
}
