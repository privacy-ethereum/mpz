//! Ideal ROLE.

use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::Field;
use mpz_ole_core::{
    ideal::{IdealROLE as Core, IdealROLEError},
    ROLEReceiver, ROLESender, ROLESenderOutput,
};

/// Ideal ROLE.
#[derive(Debug, Clone)]
pub struct IdealROLE<F> {
    core: Core<F>,
}

impl<F> IdealROLE<F>
where
    F: Field,
{
    /// Create a new ideal ROLE.
    ///
    /// # Arguments
    ///
    /// * `seed` - PRG seed.
    pub fn new(seed: Block) -> Self {
        Self {
            core: Core::new(seed),
        }
    }
}

impl<F> ROLESender<F> for IdealROLE<F>
where
    F: Field,
{
    type Error = IdealROLEError;
    type Future = <Core<F> as ROLESender<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        ROLESender::alloc(&mut self.core, count)
    }

    fn available(&self) -> usize {
        ROLESender::available(&self.core)
    }

    fn try_send_role(&mut self, count: usize) -> Result<ROLESenderOutput<F>, Self::Error> {
        self.core.try_send_role(count)
    }

    fn queue_send_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_role(count)
    }
}

impl<F> ROLEReceiver<F> for IdealROLE<F>
where
    F: Field,
{
    type Error = IdealROLEError;
    type Future = <Core<F> as ROLEReceiver<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        ROLEReceiver::alloc(&mut self.core, count)
    }

    fn available(&self) -> usize {
        ROLEReceiver::available(&self.core)
    }

    fn try_recv_role(
        &mut self,
        count: usize,
    ) -> Result<mpz_ole_core::ROLEReceiverOutput<F>, Self::Error> {
        self.core.try_recv_role(count)
    }

    fn queue_recv_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_role(count)
    }
}

#[async_trait]
impl<Ctx, F> Flush<Ctx> for IdealROLE<F>
where
    Ctx: Context,
    F: Field,
{
    type Error = IdealROLEError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, _ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.wants_flush() {
            self.core.flush()?;
        }

        Ok(())
    }
}
