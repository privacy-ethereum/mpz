use mpz_core::bitvec::{BitSlice, BitVec};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Mac, MacStore, MacStoreError},
    store::{BitStore, StoreError},
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use utils::filter_drain::FilterDrain;

use crate::{
    store::{ProverFlush, VerifierFlush},
    view::{FlushView, View, ViewError},
};

type Error = ProverStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct ProverStore {
    mac_store: MacStore,
    mask_store: BitStore,
    data_store: BitStore,
    view: View,
    pending: bool,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl ProverStore {
    pub fn new() -> Self {
        Self {
            mac_store: MacStore::default(),
            mask_store: BitStore::default(),
            data_store: BitStore::default(),
            view: View::new_prover(),
            pending: false,
            buffer_decode: Vec::default(),
        }
    }

    pub fn alloc_output(&mut self, size: usize) -> Slice {
        self.view.alloc_output(size);
        self.mac_store.alloc(size);
        self.mask_store.alloc(size);
        self.data_store.alloc(size)
    }

    /// Returns whether the MACs are set for a slice.
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        self.mac_store.is_set(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.data_store.is_set(slice)
    }

    /// Returns whether the data is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        self.view.is_committed(slice.to_range())
    }

    /// Returns `true` if the store wants MACs.
    pub fn wants_macs(&self) -> bool {
        !self.view.flush().commit.is_empty()
    }

    /// Returns the number of MACs the store wants.
    pub fn mac_count(&self) -> usize {
        self.view.flush().commit.len()
    }

    /// Returns `true` if the store wants a flush.
    pub fn wants_flush(&self) -> bool {
        self.view.wants_flush()
    }

    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mac_store.try_get(slice).map_err(Error::from)
    }

    /// Sets input MACs.
    pub fn set_macs(&mut self, masks: &BitSlice, macs: &[Mac]) -> Result<()> {
        if masks.len() != macs.len() {
            return Err(ErrorRepr::WrongMacCount {
                expected: masks.len(),
                actual: macs.len(),
            }
            .into());
        } else if masks.len() != self.view.flush().commit.len() {
            return Err(ErrorRepr::WrongMacCount {
                expected: self.view.flush().commit.len(),
                actual: masks.len(),
            }
            .into());
        }

        let mut i = 0;
        for range in self.view.flush().commit.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            self.mask_store.try_set(slice, &masks[i..i + slice.len()])?;
            self.mac_store.try_set(slice, &macs[i..i + slice.len()])?;

            let data = self.data_store.try_get(slice)?;
            self.mac_store.adjust(slice, data)?;

            i += slice.len();
        }

        Ok(())
    }

    pub fn set_output_macs(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.view.set_output(slice.to_range())?;
        self.mac_store.try_set(slice, macs)?;

        let data = BitVec::from_iter(macs.iter().map(|mac| mac.pointer()));
        self.data_store.try_set(slice, &data)?;

        Ok(())
    }

    pub fn send_flush(&mut self) -> Result<ProverFlush> {
        if self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        self.pending = true;

        // Commit MACs.
        let mut adjust = BitVec::with_capacity(self.view.flush().commit.len());
        let mut i = 0;
        for range in self.view.flush().commit.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            let data = self.data_store.try_get(slice)?;
            adjust.extend_from_bitslice(data);

            // Apply masks to the data.
            let masks = self.mask_store.try_get(slice)?;
            adjust[i..i + slice.len()] ^= masks;

            i += slice.len();
        }

        let mac_proof = if !self.view.flush().prove.is_empty() {
            Some(self.mac_store.prove(&self.view.flush().prove)?)
        } else {
            None
        };

        let flush = ProverFlush {
            view: self.view.flush().clone(),
            adjust,
            mac_proof,
        };

        Ok(flush)
    }

    pub fn receive_flush(&mut self, flush: VerifierFlush) -> Result<()> {
        if !self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let VerifierFlush { view } = flush;

        if &view != self.view.flush() {
            return Err(ErrorRepr::Flush {
                expected: self.view.flush().clone(),
                actual: view,
            }
            .into());
        }

        self.view.complete_flush(view);
        self.flush_decode()?;
        self.pending = false;

        Ok(())
    }

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

impl Memory<Binary> for ProverStore {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc_input(size);
        self.mac_store.alloc(size);
        self.mask_store.alloc(size);
        let slice = self.data_store.alloc(size);

        Ok(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.view.assign(slice.to_range())?;
        self.data_store.try_set(slice, &data)?;

        // For public data, set MACs.
        let public = slice.to_range() & self.view.visibility().public();
        for range in public.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            let data = self.data_store.try_get(slice)?;
            self.mac_store.try_set_public(slice, data)?;
        }

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
        let (fut, mut op) = DecodeFuture::new(slice);

        // If data is already decoded, send it immediately.
        if let Ok(data) = self.data_store.try_get(slice) {
            op.send(data.to_bitvec())?;
        } else {
            self.buffer_decode.push(op);
        }

        self.view.decode(slice.to_range())?;

        Ok(fut)
    }
}

impl ViewTrait<Binary> for ProverStore {
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

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProverStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    MacStore(MacStoreError),
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    View(#[from] ViewError),
    #[error("incorrect MAC count: expected {expected}, got {actual}")]
    WrongMacCount { expected: usize, actual: usize },
    #[error("store was not expecting a flush")]
    UnexpectedFlush,
    #[error("verifier flush view mismatch: expected {expected:?}, got {actual:?}")]
    Flush {
        expected: FlushView,
        actual: FlushView,
    },
}

impl From<MacStoreError> for ProverStoreError {
    fn from(err: MacStoreError) -> Self {
        Self(ErrorRepr::MacStore(err))
    }
}

impl From<StoreError> for ProverStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for ProverStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

impl From<ViewError> for ProverStoreError {
    fn from(err: ViewError) -> Self {
        Self(ErrorRepr::View(err))
    }
}
