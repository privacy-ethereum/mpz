//! This crate provides additive-to-multiplicative (A2M) and multiplicative-to-additive (M2A) share conversion protocols.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(unsafe_code)]
#![deny(clippy::all)]

mod error;
#[cfg(feature = "ideal")]
pub mod ideal;
mod receiver;
mod sender;

use async_trait::async_trait;

pub use error::ShareConversionError;
pub use receiver::ShareConversionReceiver;
pub use sender::ShareConversionSender;

/// A trait for converting additive shares into multiplicative shares.
#[async_trait]
pub trait AdditiveToMultiplicative<Ctx, T> {
    /// Converts additive shares into multiplicative shares.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `inputs` - The additive shares to convert.
    async fn to_multiplicative(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<T>,
    ) -> Result<Vec<T>, ShareConversionError>;
}

/// A trait for converting multiplicative shares into additive shares.
#[async_trait]
pub trait MultiplicativeToAdditive<Ctx, T> {
    /// Converts multiplicative shares into additive shares.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `inputs` - The multiplicative shares to convert.
    async fn to_additive(
        &mut self,
        ctx: &mut Ctx,
        inputs: Vec<T>,
    ) -> Result<Vec<T>, ShareConversionError>;
}

/// A trait for converting between additive and multiplicative shares.
pub trait ShareConvert<Ctx, T>:
    AdditiveToMultiplicative<Ctx, T> + MultiplicativeToAdditive<Ctx, T>
{
}

impl<Ctx, T, U> ShareConvert<Ctx, T> for U where
    U: AdditiveToMultiplicative<Ctx, T> + MultiplicativeToAdditive<Ctx, T>
{
}

#[cfg(test)]
mod tests {
    use crate::{
        AdditiveToMultiplicative, MultiplicativeToAdditive, ShareConversionReceiver,
        ShareConversionSender,
    };
    use mpz_common::executor::test_st_executor;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use mpz_ole::ideal::ideal_ole;
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_m2a() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (ole_sender, ole_receiver) = ideal_ole();

        let mut sender = ShareConversionSender::new(ole_sender);
        let mut receiver = ShareConversionReceiver::new(ole_receiver);

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
    async fn test_a2m() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);

        let (ole_sender, ole_receiver) = ideal_ole();

        let mut sender = ShareConversionSender::new(ole_sender);
        let mut receiver = ShareConversionReceiver::new(ole_receiver);

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
