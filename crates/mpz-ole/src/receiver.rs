use async_trait::async_trait;
use serio::{stream::IoStreamExt, Deserialize};

use mpz_common::{Context, Flush};
use mpz_fields::Field;
use mpz_ole_core::{
    ROLEReceiver, ROLEReceiverOutput, Receiver as Core, ReceiverError as CoreError,
};
use mpz_ot::rot::ROTReceiver;

/// ROLE receiver wrapping a random OT receiver.
#[derive(Debug)]
pub struct Receiver<T, F> {
    core: Core<T, F>,
}

impl<T, F> Receiver<T, F> {
    /// Creates a new ROLE receiver.
    ///
    /// # Arguments
    ///
    /// * `rot` - Random OT receiver.
    pub fn new(rot: T) -> Self {
        Self {
            core: Core::new(rot),
        }
    }

    /// Returns the random OT receiver.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T, F> ROLEReceiver<F> for Receiver<T, F>
where
    T: ROTReceiver<bool, F>,
    F: Field,
{
    type Error = ReceiverError;
    type Future = <Core<T, F> as ROLEReceiver<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count).map_err(ReceiverError::from)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn try_recv_role(&mut self, count: usize) -> Result<ROLEReceiverOutput<F>, Self::Error> {
        self.core.try_recv_role(count).map_err(ReceiverError::from)
    }

    fn queue_recv_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        self.core
            .queue_recv_role(count)
            .map_err(ReceiverError::from)
    }
}

#[async_trait]
impl< T, F> Flush for Receiver<T, F>
where
    
    T: ROTReceiver<bool, F> + Flush + Send,
    F: Field + Deserialize,
{
    type Error = ReceiverError;

    fn wants_flush(&self) -> bool {
        self.core.wants_recv()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        if self.core.rot().wants_flush() {
            self.core
                .rot_mut()
                .flush(ctx)
                .await
                .map_err(ReceiverError::ot)?;
        }

        if self.core.wants_recv() {
            let masks = ctx.io_mut().expect_next().await?;
            self.core.recv(masks)?;
        }

        Ok(())
    }
}

/// Error for [`Receiver`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ReceiverError(#[from] ErrorRepr);

impl ReceiverError {
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

impl From<CoreError> for ReceiverError {
    fn from(e: CoreError) -> Self {
        Self(ErrorRepr::Core(e))
    }
}

impl From<std::io::Error> for ReceiverError {
    fn from(e: std::io::Error) -> Self {
        Self(ErrorRepr::Io(e))
    }
}
