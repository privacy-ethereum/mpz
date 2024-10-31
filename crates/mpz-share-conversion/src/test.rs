//! Test utilities.

use mpz_common::{
    executor::{test_st_executor, TestSTExecutor},
    future::Output,
    Flush,
};
use mpz_fields::Field;
use mpz_share_conversion_core::{
    A2MOutput, AdditiveToMultiplicative, M2AOutput, MultiplicativeToAdditive, ShareConvert,
};
use rand::{rngs::StdRng, SeedableRng};

/// Test share conversion.
pub async fn test_share_convert<S, R, F>(mut sender: S, mut receiver: R, cycles: usize)
where
    S: ShareConvert<F> + Flush<TestSTExecutor>,
    R: ShareConvert<F> + Flush<TestSTExecutor>,
    F: Field,
{
    let (mut sender_ctx, mut receiver_ctx) = test_st_executor(8);
    let mut rng = StdRng::seed_from_u64(0);
    let count = 8;

    let sender_input: Vec<_> = (0..count).map(|_| F::rand(&mut rng)).collect();
    let receiver_input: Vec<_> = (0..count).map(|_| F::rand(&mut rng)).collect();

    AdditiveToMultiplicative::alloc(&mut sender, count).unwrap();
    AdditiveToMultiplicative::alloc(&mut receiver, count).unwrap();
    MultiplicativeToAdditive::alloc(&mut sender, count).unwrap();
    MultiplicativeToAdditive::alloc(&mut receiver, count).unwrap();

    let _ = sender.queue_to_multiplicative(&sender_input).unwrap();
    let _ = receiver.queue_to_multiplicative(&receiver_input).unwrap();
    let _ = sender.queue_to_additive(&sender_input).unwrap();
    let _ = receiver.queue_to_additive(&receiver_input).unwrap();

    for _ in 0..cycles {
        AdditiveToMultiplicative::alloc(&mut sender, count).unwrap();
        AdditiveToMultiplicative::alloc(&mut receiver, count).unwrap();
        MultiplicativeToAdditive::alloc(&mut sender, count).unwrap();
        MultiplicativeToAdditive::alloc(&mut receiver, count).unwrap();

        let mut sender_a2m_output = sender.queue_to_multiplicative(&sender_input).unwrap();
        let mut receiver_a2m_output = receiver.queue_to_multiplicative(&receiver_input).unwrap();
        let mut sender_m2a_output = sender.queue_to_additive(&sender_input).unwrap();
        let mut receiver_m2a_output = receiver.queue_to_additive(&receiver_input).unwrap();

        tokio::join!(
            async {
                sender.flush(&mut sender_ctx).await.unwrap();
            },
            async {
                receiver.flush(&mut receiver_ctx).await.unwrap();
            },
        );

        let A2MOutput {
            shares: sender_a2m_output,
        } = sender_a2m_output.try_recv().unwrap().unwrap();
        let A2MOutput {
            shares: receiver_a2m_output,
        } = receiver_a2m_output.try_recv().unwrap().unwrap();
        let M2AOutput {
            shares: sender_m2a_output,
        } = sender_m2a_output.try_recv().unwrap().unwrap();
        let M2AOutput {
            shares: receiver_m2a_output,
        } = receiver_m2a_output.try_recv().unwrap().unwrap();

        sender_input
            .iter()
            .zip(&receiver_input)
            .zip(sender_a2m_output)
            .zip(receiver_a2m_output)
            .for_each(|(((&si, &ri), so), ro)| assert_eq!(si + ri, so * ro));

        sender_input
            .iter()
            .zip(&receiver_input)
            .zip(sender_m2a_output)
            .zip(receiver_m2a_output)
            .for_each(|(((&si, &ri), so), ro)| assert_eq!(si * ri, so + ro));
    }
}
