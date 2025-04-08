use async_trait::async_trait;
use tokio::sync::{Mutex, OwnedMutexGuard};
use mpz_common::{Context, ContextError, Flush};
use mpz_core::{Block, bitvec::{BitVec, BitSlice}};
use mpz_garble_core::{
    Delta, Mac, Key,
    store::{AuthEvalStore as Core, AuthEvalStoreError as CoreError},
};
use mpz_memory_core::{DecodeFuture, Memory, Slice, View, binary::Binary};
use mpz_ot::cot::{COTReceiver, COTSender};
use serio::{SinkExt, stream::IoStreamExt};

type Error = AuthEvalStoreError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub(crate) struct AuthEvalStore<S, R> {
    core: Core<S, R>,
}

impl<S, R> AuthEvalStore<S, R>
{
    pub(crate) fn new(seed: [u8; 16], delta: Delta, cot_sender: S, cot_receiver: R) -> Self {
        Self { core: Core::new(seed, delta, cot_sender, cot_receiver) }
    }

    pub(crate) fn delta(&self) -> &Delta {
        self.core.delta()
    }
    
    pub(crate) fn acquire_cot_sender(&self) -> OwnedMutexGuard<S> {
        self.core.acquire_cot_sender()
    }

    pub(crate) fn acquire_cot_receiver(&self) -> OwnedMutexGuard<R> {
        self.core.acquire_cot_receiver()
    }
    
    pub(crate) fn is_set_macs(&self, slice: Slice) -> bool {
        self.core.is_set_macs(slice)
    }

    pub(crate) fn is_set_masks(&self, slice: Slice) -> bool {
        self.core.is_set_masks(slice)
    }

    pub(crate) fn is_committed(&self, slice: Slice) -> bool {
        self.core.is_committed(slice)
    }

    pub(crate) fn try_get_macs(&self, slice: Slice) -> Result<&[Mac], Error> {
        self.core.try_get_macs(slice).map_err(Error::from)
    }

    pub(crate) fn try_get_masked_values(&self, slice: Slice) -> Result<&BitSlice, Error> {
        self.core.try_get_masked_values(slice).map_err(Error::from)
    }

    pub(crate) fn try_get_mask_bits(&self, slice: Slice) -> Result<&BitSlice, Error> {
        self.core.try_get_mask_bits(slice).map_err(Error::from)
    }

    pub(crate) fn try_get_mask_macs(&self, slice: Slice) -> Result<&[Mac], Error> {
        self.core.try_get_mask_macs(slice).map_err(Error::from)
    }

    pub(crate) fn try_get_mask_keys(&self, slice: Slice) -> Result<&[Key], Error> {
        self.core.try_get_mask_keys(slice).map_err(Error::from)
    }

    pub(crate) fn alloc_output(&mut self, len: usize) -> Slice {
        self.core.alloc_output(len)
    }

    pub(crate) fn set_output(&mut self, slice: Slice, macs: &[Mac], mask_bits: &BitSlice, mask_macs: &[Mac], mask_keys: &[Key], masked_values: &BitSlice) -> Result<(), Error> {
        self.core.set_output(slice, macs, mask_bits, mask_macs, mask_keys, masked_values).map_err(Error::from)
    }

    pub(crate) fn mark_output_preprocessed(&mut self, slice: Slice) -> Result<(), Error> {
        self.core.mark_output_preprocessed(slice).map_err(Error::from)
    }

    pub(crate) fn flush_decode(&mut self) -> Result<(), Error> {
        self.core.flush_decode().map_err(Error::from)
    }
}

impl<S, R> Memory<Binary> for AuthEvalStore<S, R>
{
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

impl<S, R> View<Binary> for AuthEvalStore<S, R>
where
    S: COTSender<Block>,
    R: COTReceiver<bool, Block>,
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
impl<S, R> Flush for AuthEvalStore<S, R>
where
    S: COTSender<Block> + Flush + Send + 'static,
    R: COTReceiver<bool, Block> + Flush + Send + 'static,
    R::Future: Send + 'static,
{
    type Error = Error;

    fn wants_flush(&self) -> bool {
        self.core.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        println!("eval started flush");
        while self.core.wants_flush() {
            let flush = self.core.send_flush()?;
            let mut cot_sender = self.core.acquire_cot_sender();
            let mut cot_receiver = self.core.acquire_cot_receiver();
            println!("eval acquired cot");
            let (flush, (), ()) = ctx
            .try_join3(
                async |ctx| {
                    ctx.io_mut().send(flush).await?;
                    println!("eval sent flush");
                    ctx.io_mut().expect_next().await.map_err(Error::from)
                },
                async move |ctx| {
                    println!("eval flushing cot receiver");
                    cot_receiver.flush(ctx).await.map_err(Error::cot)
                },
                async move |ctx| {
                    println!("eval flushing cot sender");
                    cot_sender.flush(ctx).await.map_err(Error::cot)
                },
            )
            .await??;

            self.core.receive_flush(flush)?;
            println!("eval ended flush");
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct AuthEvalStoreError(#[from] ErrorRepr);

impl AuthEvalStoreError {
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

impl From<CoreError> for AuthEvalStoreError {
    fn from(value: CoreError) -> Self {
        AuthEvalStoreError(ErrorRepr::Core(value))
    }
}

impl From<std::io::Error> for AuthEvalStoreError {
    fn from(value: std::io::Error) -> Self {
        AuthEvalStoreError(ErrorRepr::Io(value))
    }
}

impl From<ContextError> for AuthEvalStoreError {
    fn from(value: ContextError) -> Self {
        AuthEvalStoreError(ErrorRepr::Context(value))
    }
}
