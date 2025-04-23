use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot_core::{
    rcot::RCOTSender,
    rot::{ROTSender, ROTSenderOutput, RandomizeRCOTSender as Core},
};

/// Randomize RCOT sender.
#[derive(Debug)]
pub struct RandomizeRCOTSender<T> {
    core: Core<T>,
}

impl<T> RandomizeRCOTSender<T> {
    /// Creates a new sender.
    pub fn new(rcot: T) -> Self {
        Self {
            core: Core::new(rcot),
        }
    }

    /// Returns the inner sender.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T> ROTSender<[Block; 2]> for RandomizeRCOTSender<T>
where
    T: RCOTSender<Block>,
{
    type Error = <Core<T> as ROTSender<[Block; 2]>>::Error;
    type Future = <Core<T> as ROTSender<[Block; 2]>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[Block; 2]>, Self::Error> {
        self.core.try_send_rot(count)
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_rot(count)
    }
}

#[async_trait]
impl<T> Flush for RandomizeRCOTSender<T>
where
    T: Flush + Send,
{
    type Error = T::Error;

    fn wants_flush(&self) -> bool {
        self.core.rcot().wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        self.core.rcot_mut().flush(ctx).await
    }
}
