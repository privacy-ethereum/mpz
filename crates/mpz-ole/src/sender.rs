use async_trait::async_trait;
use serio::{Serialize, SinkExt};

use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::Field;
use mpz_ole_core::{ROLESender, ROLESenderOutput, Sender as Core, SenderError as CoreError};
use mpz_ot::rot::ROTSender;

/// ROLE sender wrapping a random OT sender.
#[derive(Debug)]
pub struct Sender<T, F> {
    core: Core<T, F>,
}

impl<T, F> Sender<T, F> {
    /// Creates a new ROLE sender.
    ///
    /// # Arguments
    ///
    /// * `seed` - Random seed for the sender.
    /// * `rot` - Random OT sender.
    pub fn new(seed: Block, rot: T) -> Self {
        Self {
            core: Core::new(seed, rot),
        }
    }

    /// Returns the random OT sender.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T, F> ROLESender<F> for Sender<T, F>
where
    T: ROTSender<[F; 2]>,
    F: Field,
{
    type Error = SenderError;
    type Future = <Core<T, F> as ROLESender<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count).map_err(SenderError::from)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn try_send_role(&mut self, count: usize) -> Result<ROLESenderOutput<F>, Self::Error> {
        self.core.try_send_role(count).map_err(SenderError::from)
    }

    fn queue_send_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_role(count).map_err(SenderError::from)
    }
}

#[async_trait]
impl<Ctx, T, F> Flush<Ctx> for Sender<T, F>
where
    Ctx: Context,
    T: ROTSender<[F; 2]> + Flush<Ctx> + Send,
    F: Field + Serialize,
{
    type Error = SenderError;

    fn wants_flush(&self) -> bool {
        self.core.wants_send()
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.rot().wants_flush() {
            self.core
                .rot_mut()
                .flush(ctx)
                .await
                .map_err(SenderError::ot)?;
        }

        if self.core.wants_send() {
            let masks = self.core.send().map_err(SenderError::from)?;
            ctx.io_mut().send(masks).await?;
        }

        Ok(())
    }
}

/// Error for [`Sender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SenderError(#[from] ErrorRepr);

impl SenderError {
    fn ot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ot(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("ot error: {0}")]
    Ot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for SenderError {
    fn from(e: CoreError) -> Self {
        Self(ErrorRepr::Core(e))
    }
}

impl From<std::io::Error> for SenderError {
    fn from(e: std::io::Error) -> Self {
        Self(ErrorRepr::Io(e))
    }
}
