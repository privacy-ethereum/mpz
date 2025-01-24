use async_trait::async_trait;
use mpz_common::{scoped_futures::ScopedFutureExt, Context, ContextError, Flush};
use mpz_core::{bitvec::BitVec, Block};
use mpz_garble_core::{
    store::{GeneratorStore as Core, GeneratorStoreError as CoreError},
    Delta, Key,
};
use mpz_memory_core::{binary::Binary, DecodeFuture, Memory, Slice, View};
use mpz_ot::cot::COTSender;
use serio::{stream::IoStreamExt, SinkExt};

type Error = GeneratorStoreError;

#[derive(Debug)]
pub(crate) struct GeneratorStore<COT> {
    core: Core<COT>,
}

impl<COT> GeneratorStore<COT> {
    /// Creates a new generator store.
    pub(crate) fn new(seed: [u8; 16], delta: Delta, cot: COT) -> Self {
        Self {
            core: Core::new(seed, delta, cot),
        }
    }

    pub(crate) fn delta(&self) -> &Delta {
        self.core.delta()
    }

    pub(crate) fn is_committed(&self, slice: Slice) -> bool {
        self.core.is_committed(slice)
    }

    pub(crate) fn is_set_keys(&self, slice: Slice) -> bool {
        self.core.is_set_keys(slice)
    }

    pub(crate) fn try_get_keys(&self, slice: Slice) -> Result<&[Key], Error> {
        self.core.try_get_keys(slice).map_err(Error::from)
    }

    pub(crate) fn alloc_output(&mut self, size: usize) -> Slice {
        self.core.alloc_output(size)
    }

    pub(crate) fn mark_output_complete(&mut self, slice: Slice) -> Result<(), Error> {
        self.core.mark_output_complete(slice).map_err(Error::from)
    }

    pub(crate) fn set_output(&mut self, slice: Slice, keys: &[Key]) -> Result<(), Error> {
        self.core.set_output(slice, keys).map_err(Error::from)
    }
}

impl<COT> Memory<Binary> for GeneratorStore<COT> {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice, Self::Error> {
        self.core.alloc_raw(size).map_err(Error::from)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<(), Self::Error> {
        self.core.assign_raw(slice, data).map_err(Error::from)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.core.commit_raw(slice).map_err(Error::from)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>, Self::Error> {
        self.core.get_raw(slice).map_err(Error::from)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>, Self::Error> {
        self.core.decode_raw(slice).map_err(Error::from)
    }
}

impl<COT> View<Binary> for GeneratorStore<COT>
where
    COT: COTSender<Block>,
{
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.core.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.core.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<(), Self::Error> {
        self.core.mark_blind_raw(slice).map_err(Error::from)
    }
}

#[async_trait]
impl< COT> Flush for GeneratorStore<COT>
where
    
    COT: COTSender<Block> + Flush + Send + 'static,
{
    type Error = Error;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        while self.core.wants_flush() {
            let flush = self.core.send_flush()?;
            let mut cot = self.core.acquire_cot();

            let (flush, ()) = ctx
                .try_join(
                    |ctx| {
                        async move {
                            ctx.io_mut().send(flush).await?;
                            ctx.io_mut().expect_next().await.map_err(Error::from)
                        }
                        .scope_boxed()
                    },
                    |ctx| async move { cot.flush(ctx).await.map_err(Error::cot) }.scope_boxed(),
                )
                .await??;

            self.core.receive_flush(flush)?;
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct GeneratorStoreError(#[from] ErrorRepr);

impl GeneratorStoreError {
    fn cot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Cot(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("COT error: {0}")]
    Cot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("context error: {0}")]
    Context(#[from] ContextError),
}

impl From<CoreError> for GeneratorStoreError {
    fn from(value: CoreError) -> Self {
        GeneratorStoreError(ErrorRepr::Core(value))
    }
}

impl From<std::io::Error> for GeneratorStoreError {
    fn from(value: std::io::Error) -> Self {
        GeneratorStoreError(ErrorRepr::Io(value))
    }
}

impl From<ContextError> for GeneratorStoreError {
    fn from(value: ContextError) -> Self {
        GeneratorStoreError(ErrorRepr::Context(value))
    }
}
