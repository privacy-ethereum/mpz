//! Ideal functionality for random correlated OT.

use async_trait::async_trait;
<<<<<<< HEAD

use mpz_common::{
    Context, Flush,
    ideal::{CallSync, call_sync},
};
=======
use mpz_common::Flush;
>>>>>>> b81b562 (feat: lazy ot (#186))
use mpz_core::Block;
use mpz_ot_core::{
    ideal::rot::{IdealROT as Core, IdealROTError as CoreError},
    rot::{ROTReceiver, ROTReceiverOutput, ROTSender, ROTSenderOutput},
};

/// Returns a new ideal ROT sender and receiver.
pub fn ideal_rot(seed: Block) -> (IdealROTSender, IdealROTReceiver) {
    let core = Core::new(seed);
<<<<<<< HEAD
    let (sync_0, sync_1) = call_sync();
    (
        IdealROTSender {
            core: core.clone(),
            sync: sync_0,
        },
        IdealROTReceiver { core, sync: sync_1 },
=======
    (
        IdealROTSender { core: core.clone() },
        IdealROTReceiver { core },
>>>>>>> b81b562 (feat: lazy ot (#186))
    )
}

/// Ideal ROT sender.
pub struct IdealROTSender {
    core: Core,
<<<<<<< HEAD
    sync: CallSync,
=======
>>>>>>> b81b562 (feat: lazy ot (#186))
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
<<<<<<< HEAD
impl Flush for IdealROTSender {
=======
impl<Ctx> Flush<Ctx> for IdealROTSender {
>>>>>>> b81b562 (feat: lazy ot (#186))
    type Error = IdealROTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

<<<<<<< HEAD
    async fn flush(&mut self, _ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync
                .call(|| self.core.flush().map_err(IdealROTError::from))
                .await
                .transpose()?;
=======
    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush().map_err(IdealROTError::from)?;
>>>>>>> b81b562 (feat: lazy ot (#186))
        }

        Ok(())
    }
}

/// Ideal OT receiver.
pub struct IdealROTReceiver {
    core: Core,
<<<<<<< HEAD
    sync: CallSync,
=======
>>>>>>> b81b562 (feat: lazy ot (#186))
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
<<<<<<< HEAD
impl Flush for IdealROTReceiver {
=======
impl<Ctx> Flush<Ctx> for IdealROTReceiver {
>>>>>>> b81b562 (feat: lazy ot (#186))
    type Error = IdealROTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

<<<<<<< HEAD
    async fn flush(&mut self, _ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync
                .call(|| self.core.flush().map_err(IdealROTError::from))
                .await
                .transpose()?;
=======
    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush().map_err(IdealROTError::from)?;
>>>>>>> b81b562 (feat: lazy ot (#186))
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
<<<<<<< HEAD
    use rand::{Rng, SeedableRng, rngs::StdRng};
=======
    use rand::{rngs::StdRng, Rng, SeedableRng};
>>>>>>> b81b562 (feat: lazy ot (#186))

    use super::*;
    use crate::test::test_rot;

    #[tokio::test]
    async fn test_ideal_rot() {
        let mut rng = StdRng::seed_from_u64(0);
<<<<<<< HEAD
        let (sender, receiver) = ideal_rot(rng.random());
=======
        let (sender, receiver) = ideal_rot(rng.gen());
>>>>>>> b81b562 (feat: lazy ot (#186))
        test_rot(sender, receiver, 8).await;
    }
}
