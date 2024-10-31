use async_trait::async_trait;
use mpz_common::{Context, ContextError, Flush};
use mpz_core::Block;
use mpz_ot_core::cot::{DerandCOTReceiver as Core, DerandCOTReceiverError as CoreError};
use serio::{stream::IoStreamExt, SinkExt};

use crate::{cot::COTReceiver, rcot::RCOTReceiver};

type Error = DerandCOTReceiverError;

/// Derandomized COT receiver.
///
/// This is a COT receiver which derandomizes preprocessed RCOTs.
#[derive(Debug)]
pub struct DerandCOTReceiver<T> {
    core: Core<T>,
}

impl<T> DerandCOTReceiver<T> {
    /// Creates a new `DerandCOTReceiver`.
    pub fn new(rcot: T) -> Self {
        Self {
            core: Core::new(rcot),
        }
    }

    /// Returns the inner RCOT receiver.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T> COTReceiver<bool, Block> for DerandCOTReceiver<T>
where
    T: RCOTReceiver<bool, Block>,
{
    type Error = Error;
    type Future = <Core<T> as COTReceiver<bool, Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count).map_err(Error::from)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn queue_recv_cot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        self.core.queue_recv_cot(choices).map_err(Error::from)
    }
}

#[async_trait]
impl<Ctx, T> Flush<Ctx> for DerandCOTReceiver<T>
where
    Ctx: Context,
    T: RCOTReceiver<bool, Block> + Flush<Ctx> + Send,
{
    type Error = Error;

    fn wants_flush(&self) -> bool {
        self.core.wants_adjust()
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        if self.core.rcot().wants_flush() {
            self.core.rcot_mut().flush(ctx).await.map_err(Error::rcot)?;
        }

        if self.wants_flush() {
            let (derandomize, recv) = self.core.adjust()?;
            ctx.io_mut().send(derandomize).await?;
            let adjust = ctx.io_mut().expect_next().await?;
            recv.receive(adjust)?;
        }

        Ok(())
    }
}

/// Error for [`DerandCOTReceiver`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DerandCOTReceiverError(#[from] ErrorRepr);

impl DerandCOTReceiverError {
    fn rcot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Rcot(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("rcot error: {0}")]
    Rcot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("context error: {0}")]
    Context(#[from] ContextError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for DerandCOTReceiverError {
    fn from(err: CoreError) -> Self {
        Self(ErrorRepr::Core(err))
    }
}

impl From<ContextError> for DerandCOTReceiverError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}

impl From<std::io::Error> for DerandCOTReceiverError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}
