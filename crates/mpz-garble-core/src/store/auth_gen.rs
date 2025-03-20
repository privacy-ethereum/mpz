use std::sync::Arc;

use rand::Rng;
use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_common::future::Output;
use mpz_core::{bitvec::{BitVec, BitSlice}, prg::Prg, Block};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Delta, Mac, Key, KeyStore, KeyStoreError, AuthBitStore, AuthBitStoreError, AuthBit},
    store::{BitStore, StoreError},
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use mpz_ot_core::cot::{COTSender, COTReceiver, COTReceiverOutput};
use utils::filter_drain::FilterDrain;

use crate::{
    store::{EvaluatorFlush, GeneratorFlush, MacProof},
    view::{FlushView, View, ViewError},
};

type Error = AuthGenStoreError;
type Result<T> = core::result::Result<T, Error>;

struct PendingFlush {
    cot: Option<Box<dyn Output<COTReceiverOutput<Block>> + Send>>,
}

impl std::fmt::Debug for PendingFlush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingFlush").finish_non_exhaustive()
    }
}

/// Authenticated generator memory store.
#[derive(Debug)]
pub struct AuthGenStore<COT> {
    cot: Arc<Mutex<COT>>,
    prg: Prg,
    // I suspect we can remove key_store since labels are used to authenticate masked data
    key_store: KeyStore,
    mask_store: AuthBitStore,
    masked_value_store: BitStore,
    data_store: BitStore,
    view: View,
    buffer_decode: Vec<DecodeOp<BitVec>>,
    // Whether the store is waiting for a flush.
    pending: bool,
    pending_flush: Option<PendingFlush>,
}


impl<COT> AuthGenStore<COT> {
    /// Creates a new generator store.
    pub fn new(seed: [u8; 16], delta: Delta, cot: COT) -> Self {
        Self {
            cot: Arc::new(Mutex::new(cot)),
            prg: Prg::new_with_seed(seed),
            key_store: KeyStore::new(delta),
            mask_store: AuthBitStore::new(delta),
            masked_value_store: BitStore::new(),
            data_store: BitStore::new(),
            view: View::new_generator(),
            buffer_decode: Vec::new(),
            pending: false,
            pending_flush: None,
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.key_store.delta()
    }

    /// Returns a lock on the COT sender.
    pub fn acquire_cot(&self) -> OwnedMutexGuard<COT> {
        Mutex::try_lock_owned(self.cot.clone()).unwrap()
    }

    /// Returns the COT sender.
    ///
    /// # Panics
    ///
    /// Panics if a lock to the sender is still held.
    pub fn into_inner(self) -> COT {
        Arc::try_unwrap(self.cot)
            .map_err(|_| ())
            .expect("sender lock should be dropped")
            .into_inner()
    }

    /// Returns whether all the keys are set.
    pub fn is_set_keys(&self, slice: Slice) -> bool {
        self.key_store.is_set(slice)
    }

    /// Returns whether the input masks are set.
    pub fn is_set_masks(&self, slice: Slice) -> bool {
        self.mask_store.is_set(slice)
    }

    /// Returns whether the slice is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        self.view.is_committed(slice.to_range())
    }

    /// Returns keys if they are set.
    ///
    /// # Security
    ///
    /// **Never** use this method to transfer MACs to the evaluator.
    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.key_store.try_get(slice).map_err(Error::from)
    }

    /// Returns masks if they are set.
    pub fn try_get_mask_bits(&self, slice: Slice) -> Result<&BitSlice> {
        self.mask_store.try_get_bits(slice).map_err(Error::from)
    }

    /// Returns masks if they are set.
    pub fn try_get_mask_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mask_store.try_get_macs(slice).map_err(Error::from)
    }

    /// Returns masks if they are set.
    pub fn try_get_mask_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.mask_store.try_get_keys(slice).map_err(Error::from)
    }

    /// Allocates uninitialized memory for output values.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.view.alloc_output(len);
        self.key_store.alloc(len);
        self.data_store.alloc(len);
        self.masked_value_store.alloc(len);
        self.mask_store.alloc(len)
    }

    /// Sets the keys and masks for output data.
    pub fn set_output(&mut self, slice: Slice, keys: &[Key], mask_bits: &BitSlice, mask_macs: &[Mac], mask_keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys)?;
        self.mask_store.try_set_bits(slice, mask_bits)?;
        self.mask_store.try_set_macs(slice, mask_macs)?;
        self.mask_store.try_set_keys(slice, mask_keys)?;
        self.view.set_preprocessed(slice.to_range())?;

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
    fn flush_decode(&mut self) -> Result<()> {
        for mut op in self
            .buffer_decode
            .filter_drain(|op| self.data_store.is_set(op.slice))
        {
            let data = self.data_store.try_get(op.slice)?;
            op.send(data.to_bitvec())?;
        }

        Ok(())
    }
}

impl<COT> AuthGenStore<COT>
where
    COT: COTSender<Block> + COTReceiver<bool, Block>,
    <COT as COTReceiver<bool, Block>>::Future: Send + 'static,
{
    /// Sends a flush to the evaluator.
    ///
    /// This queues any necessary COTs.
    pub fn send_flush(&mut self) -> Result<()> {
        if self.pending || self.pending_flush.is_some() {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let view = self.view.flush().clone();

        // Send keys for OT.
        if !view.ot.is_empty() {
            let keys = (0..view.ot.len()).map(|_| self.prg.gen()).collect::<Vec<_>>();
            for range in view.ot.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.mask_store.try_set_keys(slice, &keys)?;
            }

            // Queue COT, we don't need the output here.
            _ = self
                .cot
                .try_lock()
                .unwrap()
                .queue_send_cot(Key::as_blocks(&keys))
                .map_err(Error::cot)?;
        }

        let cot = if !view.ot.is_empty() {
            // Collect the choices for oblivious transfer.
            let choices = (0..view.ot.len()).map(|_| self.prg.gen::<bool>()).collect::<Vec<bool>>();
            for range in view.ot.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.mask_store.try_set_bits(slice, &BitVec::from_iter(choices.iter()))?;
            }

            let output = self
                .cot
                .try_lock()
                .unwrap()
                .queue_recv_cot(&choices)
                .map_err(Error::cot)?;
            Some(Box::new(output) as Box<dyn Output<COTReceiverOutput<Block>> + Send>)
        } else {
            None
        };

        self.pending = true;
        self.pending_flush = Some(PendingFlush { cot });

        Ok(())
    }

    /// Receives a flush from the evaluator.
    pub fn receive_flush(&mut self) -> Result<()> {
        if !self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let Some(PendingFlush { cot }) = self.pending_flush.take() else {
            return Err(ErrorRepr::UnexpectedFlush.into());
        };

        let view = self.view.flush().clone();

        // Receive the MACs via COT.
        if let Some(mut cot) = cot {
            let COTReceiverOutput { msgs: macs, .. } = cot
                .try_recv()
                .map_err(Error::cot)?
                .ok_or_else(|| Error::cot("COT output is not ready"))?;
            let macs = Mac::from_blocks(macs);
            for range in view.ot.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.mask_store.try_set_macs(slice, &macs)?;
            }
        }
        
        self.pending = false;

        Ok(())
    }
}

impl<COT> Memory<Binary> for AuthGenStore<COT> {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        let keys = (0..size).map(|_| self.prg.gen()).collect::<Vec<_>>();
        self.mask_store.alloc(size);
        self.view.alloc_input(size);
        self.key_store.alloc_with(&keys);
        let slice = self.data_store.alloc(size);

        Ok(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.view.assign(slice.to_range())?;
        self.data_store.try_set(slice, &data)?;

        Ok(())
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.commit(slice.to_range()).map_err(Error::from)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.data_store
            .try_get(slice)
            .map(|data| Some(data.to_bitvec()))
            .map_err(Error::from)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.view.decode(slice.to_range())?;

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

impl<COT> ViewTrait<Binary> for AuthGenStore<COT>
where
    COT: COTSender<Block>,
{
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        // Allocate COTs for blind data.
        self.cot
            .try_lock()
            .unwrap()
            .alloc(slice.len())
            .map_err(Error::cot)?;

        self.view.mark_blind_raw(slice).map_err(Error::from)
    }
}

/// Error for [`GeneratorStore`].
#[derive(Debug, thiserror::Error)]
#[error("generator store error: {}", .0)]
pub struct AuthGenStoreError(#[from] ErrorRepr);

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
    #[error("cot error: {0}")]
    Cot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    KeyStore(KeyStoreError),
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    AuthBitStore(#[from] AuthBitStoreError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    View(#[from] ViewError),
    #[error("store was not expecting a flush")]
    UnexpectedFlush,
    #[error("inconsistent flush: expected={expected:?}, actual={actual:?}")]
    InconsistentFlush {
        expected: FlushView,
        actual: FlushView,
    },
}

impl From<KeyStoreError> for AuthGenStoreError {
    fn from(err: KeyStoreError) -> Self {
        Self(ErrorRepr::KeyStore(err))
    }
}

impl From<StoreError> for AuthGenStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<AuthBitStoreError> for AuthGenStoreError {
    fn from(err: AuthBitStoreError) -> Self {
        Self(ErrorRepr::AuthBitStore(err))
    }
}

impl From<DecodeError> for AuthGenStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

impl From<ViewError> for AuthGenStoreError {
    fn from(err: ViewError) -> Self {
        Self(ErrorRepr::View(err))
    }
}
