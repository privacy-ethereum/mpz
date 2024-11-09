use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_common::future::Output;
use mpz_core::{bitvec::BitVec, Block};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Mac, MacCommitment, MacCommitmentError, MacStore, MacStoreError, COMMIT_CIPHER},
    store::{BitStore, Store, StoreError},
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use mpz_ot_core::cot::{COTReceiver, COTReceiverOutput};
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Intersection},
};

use crate::{
    store::{EvaluatorFlush, GeneratorFlush, MacProof},
    view::{FlushView, View, ViewError},
};

type Error = EvaluatorStoreError;
type Result<T> = core::result::Result<T, Error>;

struct PendingFlush {
    cot: Option<Box<dyn Output<COTReceiverOutput<Block>> + Send>>,
}

impl std::fmt::Debug for PendingFlush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingFlush").finish_non_exhaustive()
    }
}

/// Evaluator memory store.
#[derive(Debug)]
pub struct EvaluatorStore<COT> {
    cot: Arc<Mutex<COT>>,
    mac_store: MacStore,
    key_bit_store: BitStore,
    // TODO: We need a sparse store as this takes up a lot of space.
    commit_store: Store<MacCommitment>,
    data_store: BitStore,
    view: View,
    buffer_decode: Vec<DecodeOp<BitVec>>,
    pending: Option<PendingFlush>,
}

impl<COT> EvaluatorStore<COT> {
    /// Creates a new evaluator store.
    ///
    /// # Argument
    ///
    /// * `cot` - Correlated OT receiver.
    pub fn new(cot: COT) -> Self {
        Self {
            cot: Arc::new(Mutex::new(cot)),
            mac_store: MacStore::default(),
            key_bit_store: BitStore::default(),
            commit_store: Store::default(),
            data_store: BitStore::default(),
            view: View::new_evaluator(),
            buffer_decode: Vec::default(),
            pending: None,
        }
    }

    /// Returns a lock on the COT receiver.
    pub fn acquire_cot(&self) -> OwnedMutexGuard<COT> {
        Mutex::try_lock_owned(self.cot.clone()).unwrap()
    }

    /// Returns the COT receiver.
    ///
    /// # Panics
    ///
    /// Panics if a lock to the receiver is still held.
    pub fn into_inner(self) -> COT {
        Arc::try_unwrap(self.cot)
            .map_err(|_| ())
            .expect("receiver lock should be dropped")
            .into_inner()
    }

    /// Allocates an output slice.
    pub fn alloc_output(&mut self, size: usize) -> Slice {
        self.view.alloc_output(size);
        self.mac_store.alloc(size);
        self.key_bit_store.alloc(size);
        self.commit_store.alloc(size);
        self.data_store.alloc(size)
    }

    /// Returns whether the MACs are set for a slice.
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        self.mac_store.is_set(slice)
    }

    /// Returns whether the slice is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        self.view.is_committed(slice.to_range())
    }

    /// Returns the MACs for a slice.
    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mac_store.try_get(slice).map_err(Error::from)
    }

    /// Sets the MACs for a slice corresponding to output.
    pub fn set_output(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.view.set_output(slice.to_range())?;
        self.mac_store.try_set(slice, macs)?;

        Ok(())
    }

    /// Marks an output as preprocessed.
    pub fn mark_output_preprocessed(&mut self, slice: Slice) -> Result<()> {
        self.view
            .set_preprocessed(slice.to_range())
            .map_err(Error::from)
    }

    /// Returns `true` if the store wants to flush.
    pub fn wants_flush(&self) -> bool {
        self.view.wants_flush()
    }

    /// Flushes decode operations.
    pub fn flush_decode(&mut self) -> Result<()> {
        self.decode_macs()?;

        for mut op in self
            .buffer_decode
            .filter_drain(|op| self.data_store.is_set(op.slice))
        {
            let data = self.data_store.try_get(op.slice)?;
            op.send(data.to_bitvec())?;
        }

        Ok(())
    }

    /// Decodes all data which are not set but we have the MACs and key bits.
    fn decode_macs(&mut self) -> Result<()> {
        let idx = self
            .mac_store
            .set_ranges()
            .intersection(self.key_bit_store.set_ranges())
            .difference(self.data_store.set_ranges());

        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            let mac_bits = self.mac_store.try_get_bits(slice)?;
            let mut data = self.key_bit_store.try_get(slice)?.to_bitvec();

            data.iter_mut()
                .zip(mac_bits)
                .for_each(|(mut bit, mac_bit)| {
                    *bit ^= mac_bit;
                });

            let hasher = &(*COMMIT_CIPHER);
            let start_id = slice.ptr().as_usize();
            for (i, ((mac, bit), commitment)) in self
                .mac_store
                .try_get(slice)?
                .iter()
                .zip(&data)
                .zip(self.commit_store.try_get(slice)?)
                .enumerate()
            {
                commitment.check((start_id + i) as u64, *bit, mac, hasher)?;
            }

            self.data_store.try_set(slice, &data)?;
        }

        Ok(())
    }
}

impl<COT> EvaluatorStore<COT>
where
    COT: COTReceiver<bool, Block>,
    COT::Future: Send + 'static,
{
    /// Sends a flush to the generator.
    ///
    /// This queues any necessary COTs.
    pub fn send_flush(&mut self) -> Result<EvaluatorFlush> {
        if self.pending.is_some() {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let view = self.view.flush().clone();

        let cot = if !view.ot.is_empty() {
            // Collect the choices for oblivious transfer.
            let mut choices: Vec<_> = Vec::with_capacity(view.ot.len());
            for range in view.ot.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                choices.extend(self.data_store.try_get(slice)?.iter().by_vals());
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

        // Prove decoded MACs to the generator.
        let mac_proof = if !view.decode.is_empty() {
            let (bits, proof) = self.mac_store.prove(&view.decode)?;

            Some(MacProof { bits, proof })
        } else {
            None
        };

        let flush = EvaluatorFlush { view, mac_proof };

        self.pending = Some(PendingFlush { cot });

        Ok(flush)
    }

    /// Receives flush from the generator.
    ///
    /// This expects that the COT receiver has been flushed.
    pub fn receive_flush(&mut self, flush: GeneratorFlush) -> Result<()> {
        let Some(PendingFlush { cot }) = self.pending.take() else {
            return Err(ErrorRepr::UnexpectedFlush.into());
        };

        let GeneratorFlush {
            view,
            macs,
            key_bits,
            mac_commitments,
        } = flush;

        // Ensure the generators flush is consistent.
        if &view != self.view.flush() {
            return Err(ErrorRepr::InconsistentFlush {
                expected: view,
                actual: self.view.flush().clone(),
            }
            .into());
        }

        // Receive the MACs.
        let mut i = 0;
        for range in view.macs.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.mac_store.try_set(slice, &macs[i..i + slice.len()])?;
            i += slice.len();
        }

        // Receive the MACs via COT.
        if let Some(mut cot) = cot {
            let COTReceiverOutput { msgs: macs, .. } = cot
                .try_recv()
                .map_err(Error::cot)?
                .ok_or_else(|| Error::cot("COT output is not ready"))?;
            let macs = Mac::from_blocks(macs);

            i = 0;
            for range in view.ot.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.mac_store.try_set(slice, &macs[i..i + slice.len()])?;
                i += slice.len();
            }
        }

        // Receive the decode info.
        i = 0;
        for range in view.decode_info.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.key_bit_store
                .try_set(slice, &key_bits[i..i + slice.len()])?;
            self.commit_store
                .try_set(slice, &mac_commitments[i..i + slice.len()])?;
            i += slice.len();
        }

        self.view.complete_flush(view);
        self.flush_decode()?;

        Ok(())
    }
}

impl<COT> Memory<Binary> for EvaluatorStore<COT> {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc_input(size);
        self.mac_store.alloc(size);
        self.commit_store.alloc(size);
        self.key_bit_store.alloc(size);
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
        // If data is already decoded, send it immediately.
        if let Ok(data) = self.data_store.try_get(slice) {
            op.send(data.to_bitvec())?;
        } else {
            self.buffer_decode.push(op);
        }

        Ok(fut)
    }
}

impl<COT> ViewTrait<Binary> for EvaluatorStore<COT>
where
    COT: COTReceiver<bool, Block>,
{
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        // Allocate COTs for private data.
        self.cot
            .try_lock()
            .unwrap()
            .alloc(slice.len())
            .map_err(Error::cot)?;

        self.view.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_blind_raw(slice).map_err(Error::from)
    }
}

/// Error for [`EvaluatorStore`].
#[derive(Debug, thiserror::Error)]
#[error("evaluator store error: {}", .0)]
pub struct EvaluatorStoreError(#[from] ErrorRepr);

impl EvaluatorStoreError {
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
    MacStore(MacStoreError),
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
    #[error("invalid MAC commitment: {0}")]
    MacCommitment(#[from] MacCommitmentError),
}

impl From<MacStoreError> for EvaluatorStoreError {
    fn from(err: MacStoreError) -> Self {
        Self(ErrorRepr::MacStore(err))
    }
}

impl From<StoreError> for EvaluatorStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for EvaluatorStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

impl From<ViewError> for EvaluatorStoreError {
    fn from(err: ViewError) -> Self {
        Self(ErrorRepr::View(err))
    }
}

impl From<MacCommitmentError> for EvaluatorStoreError {
    fn from(err: MacCommitmentError) -> Self {
        Self(ErrorRepr::MacCommitment(err))
    }
}
