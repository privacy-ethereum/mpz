use std::sync::Arc;

use async_trait::async_trait;
use itybity::IntoBitIterator;
use mpz_common::{sync::AsyncMutex, Context};
use mpz_core::Block;
use mpz_ot_core::{kos::msgs::SenderPayload, OTReceiverOutput, ROTReceiverOutput, TransferId};
use serio::{stream::IoStreamExt, SinkExt};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use crate::{
    kos::{Receiver, ReceiverError},
    OTError, OTReceiver, RandomOTReceiver, VerifiableOTReceiver, VerifiableOTSender,
};

/// A shared KOS receiver.
#[derive(Debug, Clone)]
pub struct SharedReceiver<BaseOT> {
    inner: Arc<AsyncMutex<Receiver<BaseOT>>>,
}

impl<BaseOT> SharedReceiver<BaseOT> {
    /// Creates a new shared receiver.
    pub fn new(receiver: Receiver<BaseOT>) -> Self {
        Self {
            // KOS receiver is always the leader.
            inner: Arc::new(AsyncMutex::new_leader(receiver)),
        }
    }
}

#[async_trait]
impl<Ctx, BaseOT> OTReceiver<Ctx, bool, Block> for SharedReceiver<BaseOT>
where
    Ctx: Context,
    BaseOT: Send,
{
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choices: &[bool],
    ) -> Result<OTReceiverOutput<Block>, OTError> {
        let mut keys = self.inner.lock(ctx).await?.take_keys(choices.len())?;

        let choices = choices.into_lsb0_vec();
        let derandomize = keys.derandomize(&choices).map_err(ReceiverError::from)?;

        // Send derandomize message
        ctx.io_mut().send(derandomize).await?;

        // Receive payload
        let payload: SenderPayload = ctx.io_mut().expect_next().await?;
        let id = payload.id;

        let msgs =
            Backend::spawn(move || keys.decrypt_blocks(payload).map_err(ReceiverError::from))
                .await?;

        Ok(OTReceiverOutput { id, msgs })
    }
}

#[async_trait]
impl<Ctx, BaseOT> RandomOTReceiver<Ctx, bool, Block> for SharedReceiver<BaseOT>
where
    Ctx: Context,
    BaseOT: Send,
{
    async fn receive_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, OTError> {
        self.inner.lock(ctx).await?.receive_random(ctx, count).await
    }
}

#[async_trait]
impl<Ctx, BaseOT> VerifiableOTReceiver<Ctx, bool, Block, [Block; 2]> for SharedReceiver<BaseOT>
where
    Ctx: Context,
    BaseOT: VerifiableOTSender<Ctx, bool, [Block; 2]> + Send,
{
    async fn verify(
        &mut self,
        ctx: &mut Ctx,
        id: TransferId,
        msgs: &[[Block; 2]],
    ) -> Result<(), OTError> {
        let record = {
            let mut inner = self.inner.lock(ctx).await?;

            // Verify delta if we haven't yet.
            if inner.state().is_extension() {
                inner.verify_delta(ctx).await?;
            }

            let receiver = inner.state().try_as_verify().map_err(ReceiverError::from)?;

            receiver.remove_record(id).map_err(ReceiverError::from)?
        };

        let msgs = msgs.to_vec();
        Backend::spawn(move || record.verify(&msgs))
            .await
            .map_err(ReceiverError::from)?;

        Ok(())
    }
}
