//! Ideal functionalities.

use async_trait::async_trait;

use mpz_common::{
    ideal::{call_sync, CallSync},
    Flush,
};
use mpz_core::Block;
use mpz_fields::Field;
use mpz_share_conversion_core::ideal::{
    ideal_share_convert as core_ideal_share_convert, IdealShareConvertError,
    IdealShareConvertReceiver as CoreReceiver, IdealShareConvertSender as CoreSender,
};

use crate::{AdditiveToMultiplicative, MultiplicativeToAdditive};

/// Create a pair of ideal share converters.
pub fn ideal_share_convert<F>(
    seed: Block,
) -> (IdealShareConvertSender<F>, IdealShareConvertReceiver<F>) {
    let (core_sender, core_receiver) = core_ideal_share_convert(seed);
    let (sync_0, sync_1) = call_sync();
    (
        IdealShareConvertSender {
            core: core_sender,
            sync: sync_0,
        },
        IdealShareConvertReceiver {
            core: core_receiver,
            sync: sync_1,
        },
    )
}

/// Ideal share conversion sender.
#[derive(Debug)]
pub struct IdealShareConvertSender<F> {
    core: CoreSender<F>,
    sync: CallSync,
}

impl<F> AdditiveToMultiplicative<F> for IdealShareConvertSender<F>
where
    F: Field,
{
    type Error = IdealShareConvertError;
    type Future = <CoreSender<F> as AdditiveToMultiplicative<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        AdditiveToMultiplicative::alloc(&mut self.core, count)
    }

    fn queue_to_multiplicative(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        self.core.queue_to_multiplicative(inputs)
    }
}

impl<F> MultiplicativeToAdditive<F> for IdealShareConvertSender<F>
where
    F: Field,
{
    type Error = IdealShareConvertError;
    type Future = <CoreSender<F> as MultiplicativeToAdditive<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        MultiplicativeToAdditive::alloc(&mut self.core, count)
    }

    fn queue_to_additive(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        self.core.queue_to_additive(inputs)
    }
}

#[async_trait]
impl<Ctx, F> Flush<Ctx> for IdealShareConvertSender<F>
where
    F: Field,
{
    type Error = IdealShareConvertError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync
                .call(|| self.core.flush().map_err(IdealShareConvertError::from))
                .await
                .transpose()?;
        }

        Ok(())
    }
}

/// Ideal share conversion receiver.
#[derive(Debug)]
pub struct IdealShareConvertReceiver<F> {
    core: CoreReceiver<F>,
    sync: CallSync,
}

impl<F> AdditiveToMultiplicative<F> for IdealShareConvertReceiver<F>
where
    F: Field,
{
    type Error = IdealShareConvertError;
    type Future = <CoreReceiver<F> as AdditiveToMultiplicative<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        AdditiveToMultiplicative::alloc(&mut self.core, count)
    }

    fn queue_to_multiplicative(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        self.core.queue_to_multiplicative(inputs)
    }
}

impl<F> MultiplicativeToAdditive<F> for IdealShareConvertReceiver<F>
where
    F: Field,
{
    type Error = IdealShareConvertError;
    type Future = <CoreReceiver<F> as MultiplicativeToAdditive<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        MultiplicativeToAdditive::alloc(&mut self.core, count)
    }

    fn queue_to_additive(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        self.core.queue_to_additive(inputs)
    }
}

#[async_trait]
impl<Ctx, F> Flush<Ctx> for IdealShareConvertReceiver<F>
where
    F: Field,
{
    type Error = IdealShareConvertError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync
                .call(|| self.core.flush().map_err(IdealShareConvertError::from))
                .await
                .transpose()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::test_share_convert;
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};

    #[tokio::test]
    async fn test_ideal_share_convert_p256() {
        let (sender, receiver) = ideal_share_convert::<P256>(Block::ZERO);
        test_share_convert(sender, receiver, 8).await;
    }

    #[tokio::test]
    async fn test_ideal_share_convert_gf2_128() {
        let (sender, receiver) = ideal_share_convert::<Gf2_128>(Block::ZERO);
        test_share_convert(sender, receiver, 8).await;
    }
}
