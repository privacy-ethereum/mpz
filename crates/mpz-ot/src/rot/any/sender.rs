use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot_core::rot::{AnySender as Core, ROTSender, ROTSenderOutput};
<<<<<<< HEAD
use rand::{distr::StandardUniform, prelude::Distribution};
=======
use rand::{distributions::Standard, prelude::Distribution};
>>>>>>> b81b562 (feat: lazy ot (#186))

/// A ROT sender which sends any type implementing `rand` traits.
#[derive(Debug)]
pub struct AnySender<T> {
    core: Core<T>,
}

impl<T> AnySender<T> {
    /// Creates a new `AnySender`.
    pub fn new(rot: T) -> Self {
        Self {
            core: Core::new(rot),
        }
    }

    /// Returns the inner sender.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T, U> ROTSender<[U; 2]> for AnySender<T>
where
    T: ROTSender<[Block; 2]>,
<<<<<<< HEAD
    StandardUniform: Distribution<U>,
=======
    Standard: Distribution<U>,
>>>>>>> b81b562 (feat: lazy ot (#186))
{
    type Error = T::Error;
    type Future = <Core<T> as ROTSender<[U; 2]>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn try_send_rot(&mut self, count: usize) -> Result<ROTSenderOutput<[U; 2]>, Self::Error> {
        self.core.try_send_rot(count)
    }

    fn queue_send_rot(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_rot(count)
    }
}

#[async_trait]
<<<<<<< HEAD
impl<T> Flush for AnySender<T>
where
    T: Flush + Send,
=======
impl<Ctx, T> Flush<Ctx> for AnySender<T>
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
