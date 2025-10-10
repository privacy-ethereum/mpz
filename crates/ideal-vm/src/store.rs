use async_trait::async_trait;
use mpz_common::{Context, ContextError, Flush};
use mpz_core::bitvec::{BitSlice, BitVec};
use mpz_memory_core::{
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
    binary::Binary,
    store::{BitStore, StoreError},
};
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};

use crate::view::{FlushView, View, ViewError};

type Error = VmStoreError;
type Result<T> = core::result::Result<T, Error>;

/// VM memory store.
#[derive(Debug)]
pub struct Store {
    data_store: BitStore,
    view: View,
    buffer_decode: Vec<DecodeOp<BitVec>>,
    // Whether the store is waiting for a flush.
    pending: bool,
}

impl Store {
    /// Creates a new store.
    pub fn new() -> Self {
        Self {
            data_store: BitStore::new(),
            view: View::new(),
            buffer_decode: Vec::new(),
            pending: false,
        }
    }

    /// Allocates uninitialized memory for output values.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.view.alloc_output(len);
        self.data_store.alloc(len)
    }

    /// Sets the output data.
    pub fn set_output(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.data_store.try_set(slice, data)?;

        Ok(())
    }

    /// Marks an output as executed.
    ///
    /// This indicates that both parties have *executed* the call which produces
    /// this output.
    pub fn mark_output_complete(&mut self, slice: Slice) -> Result<()> {
        self.view.set_output(slice.to_range()).map_err(Error::from)
    }

    /// Returns `true` if the store wants to flush.
    pub fn wants_flush(&self) -> bool {
        self.view.wants_flush()
    }

    /// Flushes decode operations.
    pub fn flush_decode(&mut self) -> Result<()> {
        for mut op in self
            .buffer_decode
            .extract_if(.., |op| self.data_store.is_set(op.slice))
        {
            let data = self.data_store.try_get(op.slice)?;
            op.send(data.to_bitvec())?;
        }

        Ok(())
    }

    /// Returns the flush view.
    pub fn flush_view(&self) -> &FlushView {
        self.view.flush()
    }

    /// Sends a flush to the peer.
    pub fn send_flush(&mut self) -> Result<FlushMsg> {
        if self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let mut input = BitVec::new();

        for inp in self.flush_view().input.iter_ranges() {
            let slice = Slice::from_range_unchecked(inp);
            let data = self.data_store.try_get(slice).expect("slice set");
            input.append(&mut data.to_bitvec());
        }

        self.pending = true;

        Ok(FlushMsg { input })
    }

    /// Receives a flush from the peer.
    pub fn receive_flush(&mut self, flush: FlushMsg) -> Result<()> {
        if !self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let FlushMsg { input: peer_input } = flush;
        let peer_ranges = self.flush_view().peer_input.clone();

        assert_eq!(peer_ranges.len(), peer_input.len());

        let mut i = 0;
        for inp in peer_ranges.iter_ranges() {
            let slice = Slice::from_range_unchecked(inp);
            self.data_store
                .try_set(slice, &peer_input[i..i + slice.len()])
                .expect("should be set");
            i += slice.len();
        }

        self.view.complete_flush();
        self.flush_decode()?;
        self.pending = false;

        Ok(())
    }
}

impl Memory<Binary> for Store {
    type Error = Error;

    fn is_alloc_raw(&self, slice: Slice) -> bool {
        self.view.is_alloc(slice.to_range())
    }

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc_input(size);
        let slice = self.data_store.alloc(size);

        Ok(slice)
    }

    fn is_assigned_raw(&self, slice: Slice) -> bool {
        self.data_store.is_set(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.view.assign(slice.to_range())?;
        self.data_store.try_set(slice, &data)?;

        Ok(())
    }

    fn is_committed_raw(&self, slice: Slice) -> bool {
        self.view.is_committed(slice.to_range())
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.commit(slice.to_range()).map_err(Error::from)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        Ok(self.data_store.get(slice).map(|data| data.to_bitvec()))
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        let (fut, mut op) = DecodeFuture::new(slice);
        // If data is already available, send it immediately.
        if let Ok(data) = self.data_store.try_get(slice) {
            op.send(data.to_bitvec())?;
        } else {
            self.buffer_decode.push(op);
        }

        Ok(fut)
    }
}

impl ViewTrait<Binary> for Store {
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_blind_raw(slice).map_err(Error::from)
    }
}

#[async_trait]
impl Flush for Store {
    type Error = Error;

    fn wants_flush(&self) -> bool {
        self.view.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<()> {
        while self.wants_flush() {
            let flush = self.send_flush()?;
            ctx.io_mut()
                .with_limit(self.flush_view().flush_size())
                .send(flush)
                .await
                .map_err(Error::from)?;

            let flush: FlushMsg = ctx
                .io_mut()
                .with_limit(self.flush_view().peer_flush_size())
                .expect_next()
                .await
                .map_err(Error::from)?;

            self.receive_flush(flush)?;
        }

        Ok(())
    }
}

/// Flush message sent by each party.
#[derive(Serialize, Deserialize)]
pub struct FlushMsg {
    /// Private inputs of the party.
    input: BitVec,
}

/// Error for [`Store`].
#[derive(Debug, thiserror::Error)]
#[error("store error: {}", .0)]
pub struct VmStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    View(#[from] ViewError),
    #[error("store was not expecting a flush")]
    UnexpectedFlush,
    #[error("context error: {0}")]
    Context(#[from] ContextError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<StoreError> for VmStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for VmStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

impl From<ViewError> for VmStoreError {
    fn from(err: ViewError) -> Self {
        Self(ErrorRepr::View(err))
    }
}

impl From<ContextError> for VmStoreError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}

impl From<std::io::Error> for VmStoreError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}
