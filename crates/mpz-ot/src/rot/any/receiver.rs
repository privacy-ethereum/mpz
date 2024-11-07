use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot_core::rot::{AnyReceiver as Core, ROTReceiver, ROTReceiverOutput};
use rand::{distributions::Standard, prelude::Distribution};

/// A ROT receiver which receives any type implementing `rand` traits.
#[derive(Debug)]
pub struct AnyReceiver<T> {
    core: Core<T>,
}

impl<T> AnyReceiver<T> {
    /// Creates a new `AnyReceiver`.
    pub fn new(rot: T) -> Self {
        Self {
            core: Core::new(rot),
        }
    }

    /// Returns the inner receiver.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T, U> ROTReceiver<bool, U> for AnyReceiver<T>
where
    T: ROTReceiver<bool, Block>,
    Standard: Distribution<U>,
{
    type Error = T::Error;
    type Future = <Core<T> as ROTReceiver<bool, U>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn try_recv_rot(&mut self, count: usize) -> Result<ROTReceiverOutput<bool, U>, Self::Error> {
        self.core.try_recv_rot(count)
    }

    fn queue_recv_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_rot(count)
    }
}

#[async_trait]
impl<Ctx, T> Flush<Ctx> for AnyReceiver<T>
where
    Ctx: Context,
    T: Flush<Ctx> + Send,
{
    type Error = T::Error;

    fn wants_flush(&self) -> bool {
        self.core.rot().wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        self.core.rot_mut().flush(ctx).await
    }
}
