use std::sync::Arc;

use async_trait::async_trait;

use mpz_common::{sync::AsyncMutex, Context};
use mpz_core::Block;
use serio::{stream::IoStreamExt as _, SinkExt as _};

use crate::{
    kos::{Sender, SenderError},
    CommittedOTReceiver, CommittedOTSender, OTError, OTReceiver, OTSender, OTSenderOutput,
    ROTSenderOutput, RandomOTSender,
};

/// A shared KOS sender.
#[derive(Debug, Clone)]
pub struct SharedSender<BaseOT> {
    inner: Arc<AsyncMutex<Sender<BaseOT>>>,
}

impl<BaseOT> SharedSender<BaseOT> {
    /// Creates a new shared sender.
    pub fn new(sender: Sender<BaseOT>) -> Self {
        Self {
            // KOS sender is always the follower.
            inner: Arc::new(AsyncMutex::new_follower(sender)),
        }
    }
}

#[async_trait]
impl<Ctx, BaseOT> OTSender<Ctx, [Block; 2]> for SharedSender<BaseOT>
where
    Ctx: Context,
    BaseOT: OTReceiver<Ctx, bool, Block> + Send + 'static,
{
    async fn send(
        &mut self,
        ctx: &mut Ctx,
        msgs: &[[Block; 2]],
    ) -> Result<OTSenderOutput, OTError> {
        let mut keys = self.inner.lock(ctx).await?.take_keys(msgs.len())?;

        let derandomize = ctx.io_mut().expect_next().await?;

        keys.derandomize(derandomize).map_err(SenderError::from)?;
        let payload = keys.encrypt_blocks(msgs).map_err(SenderError::from)?;
        let id = payload.id;

        ctx.io_mut()
            .send(payload)
            .await
            .map_err(SenderError::from)?;

        Ok(OTSenderOutput { id })
    }
}

#[async_trait]
impl<Ctx, BaseOT> RandomOTSender<Ctx, [Block; 2]> for SharedSender<BaseOT>
where
    Ctx: Context,
    BaseOT: OTReceiver<Ctx, bool, Block> + Send + 'static,
{
    async fn send_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTSenderOutput<[Block; 2]>, OTError> {
        self.inner.lock(ctx).await?.send_random(ctx, count).await
    }
}

#[async_trait]
impl<Ctx, BaseOT> CommittedOTSender<Ctx, [Block; 2]> for SharedSender<BaseOT>
where
    Ctx: Context,
    BaseOT: CommittedOTReceiver<Ctx, bool, Block> + Send + 'static,
{
    async fn reveal(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        self.inner
            .lock(ctx)
            .await?
            .reveal(ctx)
            .await
            .map_err(OTError::from)
    }
}
