use async_trait::async_trait;
use mpz_common::{Context, ContextError, Flush};
use mpz_core::Block;
use mpz_ot_core::cot::{DerandCOTSender as Core, DerandCOTSenderError as CoreError};
use serio::{stream::IoStreamExt, SinkExt};

use crate::{cot::COTSender, rcot::RCOTSender};

type Error = DerandCOTSenderError;

/// Derandomized COT sender.
///
/// This is a COT sender which derandomizes preprocessed RCOTs.
#[derive(Debug)]
pub struct DerandCOTSender<T> {
    core: Core<T>,
}

impl<T> DerandCOTSender<T> {
    /// Creates a new `DerandCOTSender`.
    pub fn new(rcot: T) -> Self {
        Self {
            core: Core::new(rcot),
        }
    }

    /// Returns the inner RCOT sender.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T> COTSender<Block> for DerandCOTSender<T>
where
    T: RCOTSender<Block>,
{
    type Error = Error;
    type Future = <Core<T> as COTSender<Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.core.alloc(count).map_err(Error::from)
    }

    fn available(&self) -> usize {
        self.core.available()
    }

    fn delta(&self) -> Block {
        self.core.delta()
    }

    fn queue_send_cot(&mut self, keys: &[Block]) -> Result<Self::Future, Self::Error> {
        self.core.queue_send_cot(keys).map_err(Error::from)
    }
}

#[async_trait]
impl<Ctx, T> Flush<Ctx> for DerandCOTSender<T>
where
    Ctx: Context,
    T: RCOTSender<Block> + Flush<Ctx> + Send,
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
            let derandomize = ctx.io_mut().expect_next().await?;
            let adjust = self.core.adjust(derandomize)?;
            ctx.io_mut().send(adjust).await?;
        }

        Ok(())
    }
}

/// Error for [`DerandCOTSender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DerandCOTSenderError(#[from] ErrorRepr);

impl DerandCOTSenderError {
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

impl From<CoreError> for DerandCOTSenderError {
    fn from(err: CoreError) -> Self {
        Self(ErrorRepr::Core(err))
    }
}

impl From<ContextError> for DerandCOTSenderError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}

impl From<std::io::Error> for DerandCOTSenderError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}
