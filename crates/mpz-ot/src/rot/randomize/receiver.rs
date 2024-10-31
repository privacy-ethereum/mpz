use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot_core::{
    rcot::RCOTReceiver,
    rot::{ROTReceiver, ROTReceiverOutput, RandomizeRCOTReceiver as Core},
};

/// Randomize RCOT receiver.
#[derive(Debug)]
pub struct RandomizeRCOTReceiver<T> {
    core: Core<T>,
}

impl<T> RandomizeRCOTReceiver<T> {
    /// Creates a new receiver.
    pub fn new(rcot: T) -> Self {
        Self {
            core: Core::new(rcot),
        }
    }

    /// Returns the inner receiver.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T> ROTReceiver<bool, Block> for RandomizeRCOTReceiver<T>
where
    T: RCOTReceiver<bool, Block>,
{
    type Error = <Core<T> as ROTReceiver<bool, Block>>::Error;
    type Future = <Core<T> as ROTReceiver<bool, Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn try_recv_rot(
        &mut self,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, Block>, Self::Error> {
        self.core.try_recv_rot(count)
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_rot(count)
    }
}

#[async_trait]
impl<Ctx, T> Flush<Ctx> for RandomizeRCOTReceiver<T>
where
    Ctx: Context,
    T: Flush<Ctx> + Send,
{
    type Error = T::Error;

    fn wants_flush(&self) -> bool {
        self.core.rcot().wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        self.core.rcot_mut().flush(ctx).await
    }
}
