//! Provides an implementation of ROLEe based on random OT.

mod evaluator;
mod provider;

pub use evaluator::ROLEeEvaluator;
pub use provider::ROLEeProvider;

#[cfg(test)]
mod tests {
    use super::{ROLEeEvaluator, ROLEeProvider};
    use crate::{RandomOLEeEvaluate, RandomOLEeProvide};
    use futures::StreamExt;
    use mpz_ot::ideal::ideal_random_ot_pair;
    use mpz_share_conversion_core::fields::p256::P256;
    use utils_aio::duplex::MemoryDuplex;

    #[tokio::test]
    async fn test_role() {
        let count = 12;
        let (sender_channel, receiver_channel) = MemoryDuplex::new();

        let (mut provider_sink, mut provider_stream) = sender_channel.split();
        let (mut evaluator_sink, mut evaluator_stream) = receiver_channel.split();

        let (rot_sender, rot_receiver) = ideal_random_ot_pair::<[u8; 32]>([0; 32]);

        let mut role_provider = ROLEeProvider::<32, _, P256>::new(rot_sender);
        let mut role_evaluator = ROLEeEvaluator::<32, _, P256>::new(rot_receiver);

        let (provider_res, evaluator_res) = tokio::join!(
            role_provider.provide_random(&mut provider_sink, &mut provider_stream, count),
            role_evaluator.evaluate_random(&mut evaluator_sink, &mut evaluator_stream, count)
        );

        let (ak, xk) = provider_res.unwrap();
        let (bk, yk) = evaluator_res.unwrap();

        ak.iter()
            .zip(bk)
            .zip(xk)
            .zip(yk)
            .for_each(|(((&a, b), x), y)| assert_eq!(y, a * b + x));
    }
}
