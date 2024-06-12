//! Ideal share conversion.

use async_trait::async_trait;

use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Allocate, Context, Preprocess,
};
use mpz_fields::Field;
use mpz_share_conversion_core::ideal::{IdealA2M, IdealM2A};

use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionError};

#[derive(Debug, Default)]
struct Inner {
    m2a: IdealM2A,
    a2m: IdealA2M,
}

#[derive(Debug)]
enum Role {
    Alice(Alice<Inner>),
    Bob(Bob<Inner>),
}

/// An ideal share converter.
#[derive(Debug)]
pub struct IdealShareConverter(Role);

impl Allocate for IdealShareConverter {
    fn alloc(&mut self, _: usize) {}
}

#[async_trait]
impl<Ctx> Preprocess<Ctx> for IdealShareConverter
where
    Ctx: Context,
{
    type Error = ShareConversionError;

    async fn preprocess(&mut self, _ctx: &mut Ctx) -> Result<(), ShareConversionError> {
        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context, F: Field> AdditiveToMultiplicative<Ctx, F> for IdealShareConverter {
    async fn to_multiplicative(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, ShareConversionError> {
        Ok(match &mut self.0 {
            Role::Alice(alice) => {
                alice
                    .call(ctx, inputs, |inner, a, b: Vec<F>| inner.a2m.generate(a, b))
                    .await
            }
            Role::Bob(bob) => {
                bob.call(ctx, inputs, |inner, a: Vec<F>, b| inner.a2m.generate(a, b))
                    .await
            }
        })
    }
}

#[async_trait]
impl<Ctx: Context, F: Field> MultiplicativeToAdditive<Ctx, F> for IdealShareConverter {
    async fn to_additive(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<F>,
    ) -> Result<Vec<F>, ShareConversionError> {
        Ok(match &mut self.0 {
            Role::Alice(alice) => {
                alice
                    .call(ctx, inputs, |inner, a, b: Vec<F>| inner.m2a.generate(a, b))
                    .await
            }
            Role::Bob(bob) => {
                bob.call(ctx, inputs, |inner, a: Vec<F>, b| inner.m2a.generate(a, b))
                    .await
            }
        })
    }
}

/// Creates a pair of ideal share converters.
pub fn ideal_share_converter() -> (IdealShareConverter, IdealShareConverter) {
    let (alice, bob) = ideal_f2p(Inner::default());

    (
        IdealShareConverter(Role::Alice(alice)),
        IdealShareConverter(Role::Bob(bob)),
    )
}

#[cfg(test)]
mod tests {
    use crate::{ideal::ideal_share_converter, AdditiveToMultiplicative, MultiplicativeToAdditive};
    use mpz_common::executor::test_st_executor;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_ideal_m2a() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (mut sender, mut receiver) = ideal_share_converter();

        let sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(10);

        let (sender_output, receiver_output) = tokio::try_join!(
            sender.to_additive(&mut ctx_sender, sender_input.clone()),
            receiver.to_additive(&mut ctx_receiver, receiver_input.clone())
        )
        .unwrap();

        sender_input
            .iter()
            .zip(receiver_input)
            .zip(sender_output)
            .zip(receiver_output)
            .for_each(|(((&si, ri), so), ro)| assert_eq!(si * ri, so + ro));
    }

    #[tokio::test]
    async fn test_ideal_a2m() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (mut sender, mut receiver) = ideal_share_converter();

        let sender_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let receiver_input: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(10);

        let (sender_output, receiver_output) = tokio::try_join!(
            sender.to_multiplicative(&mut ctx_sender, sender_input.clone()),
            receiver.to_multiplicative(&mut ctx_receiver, receiver_input.clone())
        )
        .unwrap();

        sender_input
            .iter()
            .zip(receiver_input)
            .zip(sender_output)
            .zip(receiver_output)
            .for_each(|(((&si, ri), so), ro)| assert_eq!(si + ri, so * ro));
    }
}
