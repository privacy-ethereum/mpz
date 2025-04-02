use async_trait::async_trait;
use mpz_common::{scoped_futures::ScopedFutureExt, Context, ContextError, Flush};
use mpz_core::{bitvec::{BitVec, BitSlice}, Block};
use mpz_garble_core::{
    store::{AuthGenStore as Core, AuthGenStoreError as CoreError},
    Delta, Key, Mac,
};
use mpz_memory_core::{binary::Binary, DecodeFuture, Memory, Slice, View};
use mpz_ot::cot::{COTReceiver, COTSender};
use serio::{stream::IoStreamExt, SinkExt};

type Error = CoreError;

#[derive(Debug)]
pub(crate) struct AuthGenStore<S,R> {
    core: Core<S,R>,
}

impl<S,R> AuthGenStore<S,R>
where
    S: COTSender<Block>,
    R: COTReceiver<bool, Block>,
    R::Future: Send + 'static,
{
    /// Creates a new generator store.
    pub(crate) fn new(seed: [u8; 16], delta: Delta, cot_send: S, cot_recv: R) -> Self {
        Self {
            core: Core::new(seed, delta, cot_send, cot_recv),
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

    pub(crate) fn set_output(&mut self, slice: Slice, keys: &[Key], mask_bits: &BitSlice, mask_macs: &[Mac], mask_keys: &[Key]) -> Result<(), Error> {
        self.core.set_output(slice, keys, mask_bits, mask_macs, mask_keys).map_err(Error::from)
    }
}

impl<S,R> Memory<Binary> for AuthGenStore<S,R> {
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

impl<S,R> View<Binary> for AuthGenStore<S,R>
where
    S: COTSender<Block>,
    R: COTReceiver<bool, Block>,
    R::Future: Send + 'static,
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
impl<S,R> Flush for AuthGenStore<S,R>
where
    S: COTSender<Block> + Flush + Send + 'static,
    R: COTReceiver<bool, Block> + Flush + Send + 'static,
{
    type Error = AuthGenStoreError;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        while self.core.wants_flush() {
            let flush = self.core.send_flush().map_err(AuthGenStoreError::from)?;
            let mut sender_cot = self.core.acquire_cot_sender();
            let mut receiver_cot = self.core.acquire_cot_receiver();

            let (flush, ()) = ctx
                .try_join(
                    |ctx| {
                        async move {
                            ctx.io_mut().send(flush).await.map_err(AuthGenStoreError::from)?;
                            ctx.io_mut().expect_next().await.map_err(AuthGenStoreError::from)
                        }
                        .scope_boxed()
                    },
                    |ctx| async move { 
                        sender_cot.flush(ctx).await.map_err(AuthGenStoreError::cot)?;
                        receiver_cot.flush(ctx).await.map_err(AuthGenStoreError::cot)?;
                        Ok(())
                    }.scope_boxed(),
                )
                .await??;

            self.core.receive_flush(flush).map_err(AuthGenStoreError::from)?;
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct AuthGenStoreError(#[from] ErrorRepr);

impl AuthGenStoreError {
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

impl From<CoreError> for AuthGenStoreError {
    fn from(value: CoreError) -> Self {
        AuthGenStoreError(ErrorRepr::Core(value))
    }
}

impl From<std::io::Error> for AuthGenStoreError {
    fn from(value: std::io::Error) -> Self {
        AuthGenStoreError(ErrorRepr::Io(value))
    }
}

impl From<ContextError> for AuthGenStoreError {
    fn from(value: ContextError) -> Self {
        AuthGenStoreError(ErrorRepr::Context(value))
    }
}
