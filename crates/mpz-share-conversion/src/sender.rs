use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_fields::Field;
use mpz_ole::ROLESender;
use mpz_share_conversion_core::{
    AdditiveToMultiplicative, MultiplicativeToAdditive, Sender as Core, SenderError as CoreError,
};
use serio::{stream::IoStreamExt, Deserialize, Serialize, SinkExt};

/// Share conversion sender.
#[derive(Debug)]
pub struct ShareConversionSender<T, F> {
    core: Core<T, F>,
}

impl<T, F> ShareConversionSender<T, F> {
    /// Creates a new sender.
    ///
    /// # Arguments
    ///
    /// * `role` - ROLE sender.
    pub fn new(role: T) -> Self {
        Self {
            core: Core::new(role),
        }
    }

    /// Returns the ROLE sender.
    pub fn into_inner(self) -> T {
        self.core.into_inner()
    }
}

impl<T, F> AdditiveToMultiplicative<F> for ShareConversionSender<T, F>
where
    T: ROLESender<F>,
    F: Field,
{
    type Error = SenderError;
    type Future = <Core<T, F> as AdditiveToMultiplicative<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        AdditiveToMultiplicative::alloc(&mut self.core, count).map_err(SenderError::from)
    }

    fn queue_to_multiplicative(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        self.core
            .queue_to_multiplicative(inputs)
            .map_err(SenderError::from)
    }
}

impl<T, F> MultiplicativeToAdditive<F> for ShareConversionSender<T, F>
where
    T: ROLESender<F>,
    F: Field,
{
    type Error = SenderError;
    type Future = <Core<T, F> as MultiplicativeToAdditive<F>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        MultiplicativeToAdditive::alloc(&mut self.core, count).map_err(SenderError::from)
    }

    fn queue_to_additive(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        self.core
            .queue_to_additive(inputs)
            .map_err(SenderError::from)
    }
}

#[async_trait]
impl< T, F> Flush for ShareConversionSender<T, F>
where
    
    T: ROLESender<F> + Flush + Send,
    F: Field + Serialize + Deserialize,
{
    type Error = SenderError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), SenderError> {
        if self.core.role().wants_flush() {
            self.core
                .role_mut()
                .flush(ctx)
                .await
                .map_err(SenderError::role)?;
        }

        let wants_m2a = self.core.wants_m2a();
        let wants_a2m = self.core.wants_a2m();

        if wants_m2a {
            ctx.io_mut().send(self.core.send_m2a()?).await?;
            let msg = ctx.io_mut().expect_next().await?;
            self.core.recv_m2a(msg)?;
        }

        if wants_a2m {
            let msg = ctx.io_mut().expect_next().await?;
            self.core.recv_a2m(msg)?;
            ctx.io_mut().send(self.core.send_a2m()?).await?;
        }

        Ok(())
    }
}

/// Error for [`ShareConversionSender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SenderError(#[from] ErrorRepr);

impl SenderError {
    fn role<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Role(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("role error: {0}")]
    Role(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for SenderError {
    fn from(value: CoreError) -> Self {
        SenderError(ErrorRepr::Core(value))
    }
}

impl From<std::io::Error> for SenderError {
    fn from(value: std::io::Error) -> Self {
        SenderError(ErrorRepr::Io(value))
    }
}
