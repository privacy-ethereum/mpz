//! Ideal functionality for chosen-message oblivious transfer.

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
    ideal::ot::{IdealOT as Core, IdealOTError as CoreError},
    ot::{OTReceiver, OTSender},
};

/// Returns a new ideal OT sender and receiver.
pub fn ideal_ot() -> (IdealOTSender, IdealOTReceiver) {
    let core = Core::new();
<<<<<<< HEAD
    let (sync_0, sync_1) = call_sync();
    (
        IdealOTSender {
            core: core.clone(),
            sync: sync_0,
        },
        IdealOTReceiver { core, sync: sync_1 },
=======
    (
        IdealOTSender { core: core.clone() },
        IdealOTReceiver { core },
>>>>>>> b81b562 (feat: lazy ot (#186))
    )
}

/// Ideal OT sender.
pub struct IdealOTSender {
    core: Core,
<<<<<<< HEAD
    sync: CallSync,
=======
>>>>>>> b81b562 (feat: lazy ot (#186))
}

impl OTSender<Block> for IdealOTSender {
    type Error = IdealOTError;
    type Future = <Core as OTSender<Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        OTSender::alloc(&mut self.core, count).map_err(From::from)
    }

    fn queue_send_ot(&mut self, msgs: &[[Block; 2]]) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_ot(msgs).map_err(From::from)
    }
}

#[async_trait]
<<<<<<< HEAD
impl Flush for IdealOTSender {
=======
impl<Ctx> Flush<Ctx> for IdealOTSender {
>>>>>>> b81b562 (feat: lazy ot (#186))
    type Error = IdealOTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

<<<<<<< HEAD
    async fn flush(&mut self, _ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync
                .call(|| self.core.flush().map_err(IdealOTError::from))
                .await
                .transpose()?;
=======
    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush().map_err(IdealOTError::from)?;
>>>>>>> b81b562 (feat: lazy ot (#186))
        }

        Ok(())
    }
}

/// Ideal OT receiver.
pub struct IdealOTReceiver {
    core: Core,
<<<<<<< HEAD
    sync: CallSync,
=======
>>>>>>> b81b562 (feat: lazy ot (#186))
}

impl OTReceiver<bool, Block> for IdealOTReceiver {
    type Error = IdealOTError;
    type Future = <Core as OTReceiver<bool, Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        OTReceiver::alloc(&mut self.core, count).map_err(From::from)
    }

    fn queue_recv_ot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_ot(choices).map_err(From::from)
    }
}

#[async_trait]
<<<<<<< HEAD
impl Flush for IdealOTReceiver {
=======
impl<Ctx> Flush<Ctx> for IdealOTReceiver {
>>>>>>> b81b562 (feat: lazy ot (#186))
    type Error = IdealOTError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

<<<<<<< HEAD
    async fn flush(&mut self, _ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.sync
                .call(|| self.core.flush().map_err(IdealOTError::from))
                .await
                .transpose()?;
=======
    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush().map_err(IdealOTError::from)?;
>>>>>>> b81b562 (feat: lazy ot (#186))
        }

        Ok(())
    }
}

/// Ideal OT error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct IdealOTError(#[from] CoreError);
