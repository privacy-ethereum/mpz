use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot_core::rot::{AnyReceiver as Core, ROTReceiver, ROTReceiverOutput};
<<<<<<< HEAD
use rand::{distr::StandardUniform, prelude::Distribution};

/// A ROT receiver which receives any type implementing `rand` traits.
=======
use rand::{distributions::Standard, prelude::Distribution};

/// A ROT receiver which recvs any type implementing `rand` traits.
>>>>>>> b81b562 (feat: lazy ot (#186))
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
<<<<<<< HEAD
    StandardUniform: Distribution<U>,
=======
    Standard: Distribution<U>,
>>>>>>> b81b562 (feat: lazy ot (#186))
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
<<<<<<< HEAD
impl<T> Flush for AnyReceiver<T>
where
    T: Flush + Send,
=======
impl<Ctx, T> Flush<Ctx> for AnyReceiver<T>
where
    Ctx: Context,
    T: Flush<Ctx> + Send,
>>>>>>> b81b562 (feat: lazy ot (#186))
{
    type Error = T::Error;

    fn wants_flush(&self) -> bool {
        self.core.rot().wants_flush()
    }

<<<<<<< HEAD
    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
=======
    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
>>>>>>> b81b562 (feat: lazy ot (#186))
        self.core.rot_mut().flush(ctx).await
    }
}
