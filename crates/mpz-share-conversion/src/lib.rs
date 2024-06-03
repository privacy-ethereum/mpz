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
