//! Ideal functionality for random correlated OT.

use async_trait::async_trait;
use mpz_common::Flush;
use mpz_core::Block;
use mpz_ot_core::{
    ideal::rot::{IdealROT as Core, IdealROTError as CoreError},
    rot::{ROTReceiver, ROTReceiverOutput, ROTSender, ROTSenderOutput},
};

/// Returns a new ideal ROT sender and receiver.
pub fn ideal_rot(seed: Block) -> (IdealROTSender, IdealROTReceiver) {
    let core = Core::new(seed);
    (
        IdealROTSender { core: core.clone() },
        IdealROTReceiver { core },
    )
}

/// Ideal ROT sender.
pub struct IdealROTSender {
    core: Core,
}

impl ROTSender<[Block; 2]> for IdealROTSender {
    type Error = IdealROTError;
    type Future = <Core as ROTSender<[Block; 2]>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        ROTSender::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        ROTSender::available(&self.core)
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[Block; 2]>, Self::Error> {
        self.core.try_send_rot(count).map_err(From::from)
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_rot(count).map_err(From::from)
    }
}

#[async_trait]
impl<Ctx> Flush<Ctx> for IdealROTSender {
    type Error = IdealROTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush().map_err(IdealROTError::from)?;
        }

        Ok(())
    }
}

/// Ideal OT receiver.
pub struct IdealROTReceiver {
    core: Core,
}

impl ROTReceiver<bool, Block> for IdealROTReceiver {
    type Error = IdealROTError;
    type Future = <Core as ROTReceiver<bool, Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        ROTReceiver::alloc(&mut self.core, count).map_err(From::from)
    }

    fn available(&self) -> usize {
        ROTReceiver::available(&self.core)
    }

    fn try_recv_rot(
        &mut self,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, Self::Error> {
        self.core.try_recv_rot(count).map_err(From::from)
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_rot(count).map_err(From::from)
    }
}

#[async_trait]
impl<Ctx> Flush<Ctx> for IdealROTReceiver {
    type Error = IdealROTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush().map_err(IdealROTError::from)?;
        }

        Ok(())
    }
}

/// Ideal OT error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct IdealROTError(#[from] CoreError);

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::test::test_rot;

    #[tokio::test]
    async fn test_ideal_rot() {
        let mut rng = StdRng::seed_from_u64(0);
        let (sender, receiver) = ideal_rot(rng.gen());
        test_rot(sender, receiver, 8).await;
    }
}
