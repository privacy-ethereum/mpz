use std::sync::Arc;

use rand::Rng;
use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_core::{bitvec::BitVec, prg::Prg, Block};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Delta, Key, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use mpz_ot_core::cot::COTSender;
use utils::filter_drain::FilterDrain;

use crate::{
    store::{EvaluatorFlush, GeneratorFlush, MacProof},
    view::{FlushView, View, ViewError},
};

type Error = GeneratorStoreError;
type Result<T> = core::result::Result<T, Error>;

/// Generator memory store.
#[derive(Debug)]
pub struct GeneratorStore<COT> {
    cot: Arc<Mutex<COT>>,
    prg: Prg,
    key_store: KeyStore,
    data_store: BitStore,
    view: View,
    buffer_decode: Vec<DecodeOp<BitVec>>,
    // Whether the store is waiting for a flush.
    pending: bool,
}

impl<COT> GeneratorStore<COT> {
    /// Creates a new generator store.
    pub fn new(seed: [u8; 16], delta: Delta, cot: COT) -> Self {
        Self {
            cot: Arc::new(Mutex::new(cot)),
            prg: Prg::new_with_seed(seed),
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            view: View::new_generator(),
            buffer_decode: Vec::new(),
            pending: false,
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

    /// Allocates uninitialized memory for output values.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.view.alloc_output(len);
        self.key_store.alloc(len);
        self.data_store.alloc(len)
    }

    /// Sets the keys for output data.
    pub fn set_output(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys)?;
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

impl<COT> GeneratorStore<COT>
where
    COT: COTSender<Block>,
{
    /// Sends a flush to the evaluator.
    ///
    /// This queues any necessary COTs.
    pub fn send_flush(&mut self) -> Result<GeneratorFlush> {
        if self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let view = self.view.flush().clone();

        // Collect MACs.
        let mut macs = Vec::with_capacity(view.macs.len());
        for range in view.macs.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let data = self.data_store.try_get(slice)?;
            macs.extend(self.key_store.authenticate(slice, data)?);
        }

        // Send keys for OT.
        if !view.ot.is_empty() {
            let mut keys = Vec::with_capacity(view.ot.len());
            for range in view.ot.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                keys.extend_from_slice(self.key_store.oblivious_transfer(slice)?);
            }

            // Queue COT, we don't need the output here.
            _ = self
                .cot
                .try_lock()
                .unwrap()
                .queue_send_cot(Key::as_blocks(&keys))
                .map_err(Error::cot)?;
        }

        // Collect key bits.
        let mut key_bits = BitVec::with_capacity(view.decode_info.len());
        for range in view.decode_info.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            key_bits.extend(self.key_store.try_get_bits(slice)?);
        }

        // Collect MAC commitments.
        let mut mac_commitments = Vec::with_capacity(view.decode_info.len());
        for range in view.decode_info.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            mac_commitments.extend(self.key_store.commit(slice)?);
        }

        let flush = GeneratorFlush {
            view,
            macs,
            key_bits,
            mac_commitments,
        };

        self.pending = true;

        Ok(flush)
    }

    /// Receives a flush from the evaluator.
    pub fn receive_flush(&mut self, flush: EvaluatorFlush) -> Result<()> {
        if !self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let EvaluatorFlush {
            view,
            mac_proof: macs,
        } = flush;

        // Ensure the evaluators view is consistent.
        if &view != self.view.flush() {
            return Err(ErrorRepr::InconsistentFlush {
                expected: self.view.flush().clone(),
                actual: view.clone(),
            }
            .into());
        }

        // Verify MACs and store the data.
        if let Some(MacProof { mut bits, proof }) = macs {
            self.key_store.verify(&view.decode, &mut bits, proof)?;

            let mut i = 0;
            for range in view.decode.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.data_store.try_set(slice, &bits[i..i + slice.len()])?;
                i += slice.len();
            }
        }

        self.view.complete_flush(view);
        self.flush_decode()?;
        self.pending = false;

        Ok(())
    }
}

impl<COT> Memory<Binary> for GeneratorStore<COT> {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        let keys = (0..size).map(|_| self.prg.gen()).collect::<Vec<_>>();
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

impl<COT> ViewTrait<Binary> for GeneratorStore<COT>
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
pub struct GeneratorStoreError(#[from] ErrorRepr);

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
    #[error("cot error: {0}")]
    Cot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    KeyStore(KeyStoreError),
    #[error(transparent)]
    Store(StoreError),
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

impl From<KeyStoreError> for GeneratorStoreError {
    fn from(err: KeyStoreError) -> Self {
        Self(ErrorRepr::KeyStore(err))
    }
}

impl From<StoreError> for GeneratorStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for GeneratorStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

impl From<ViewError> for GeneratorStoreError {
    fn from(err: ViewError) -> Self {
        Self(ErrorRepr::View(err))
    }
}
