use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::Binary,
    correlated::{Delta, Key, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use utils::filter_drain::FilterDrain;

use crate::{
    store::{ProverFlush, VerifierFlush},
    view::{FlushView, View, ViewError},
};

type Error = VerifierStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct VerifierStore {
    key_store: KeyStore,
    data_store: BitStore,
    view: View,
    pending: bool,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl VerifierStore {
    /// Creates a new verifier store.
    pub fn new(delta: Delta) -> Self {
        Self {
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            view: View::new_verifier(),
            pending: false,
            buffer_decode: Vec::new(),
        }
    }

    pub fn alloc_output(&mut self, size: usize) -> Slice {
        self.view.alloc_output(size);
        self.key_store.alloc(size);
        self.data_store.alloc(size)
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.key_store.delta()
    }

    /// Returns whether the data is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        self.view.is_committed(slice.to_range())
    }

    /// Returns `true` if the store wants keys.
    pub fn wants_keys(&self) -> bool {
        !self.view.flush().commit.is_empty()
    }

    /// Returns the number of keys the store wants.
    pub fn key_count(&self) -> usize {
        self.view.flush().commit.len()
    }

    /// Returns `true` if the store wants a flush.
    pub fn wants_flush(&self) -> bool {
        self.view.wants_flush()
    }

    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.key_store.try_get(slice).map_err(Error::from)
    }

    pub fn set_keys(&mut self, keys: &[Key]) -> Result<()> {
        if keys.len() != self.key_count() {
            return Err(ErrorRepr::WrongKeyCount {
                expected: self.key_count(),
                actual: keys.len(),
            }
            .into());
        }

        let mut i = 0;
        for range in self.view.flush().commit.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            self.key_store.try_set(slice, &keys[i..i + slice.len()])?;

            i += slice.len();
        }

        Ok(())
    }

    /// Sets the output keys for a circuit.
    pub fn set_output_keys(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.view.set_output(slice.to_range())?;
        self.key_store.try_set(slice, keys)?;

        Ok(())
    }

    pub fn send_flush(&mut self) -> Result<VerifierFlush> {
        if self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        self.pending = true;

        let flush = VerifierFlush {
            view: self.view.flush().clone(),
        };

        Ok(flush)
    }

    pub fn receive_flush(&mut self, flush: ProverFlush) -> Result<()> {
        if !self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let ProverFlush {
            view,
            adjust,
            mac_proof,
        } = flush;

        if &view != self.view.flush() {
            return Err(ErrorRepr::Flush {
                expected: self.view.flush().clone(),
                actual: view,
            }
            .into());
        }

        // Adjust keys.
        let mut i = 0;
        for range in view.commit.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.key_store.adjust(slice, &adjust[i..i + slice.len()])?;
            i += slice.len();
        }

        // Verify MAC proofs.
        i = 0;
        if let Some((mut bits, proof)) = mac_proof {
            self.key_store.verify(&view.prove, &mut bits, proof)?;
            for range in view.prove.iter_ranges() {
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

impl Memory<Binary> for VerifierStore {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc_input(size);
        self.key_store.alloc(size);
        let slice = self.data_store.alloc(size);

        Ok(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.view.assign(slice.to_range())?;
        self.data_store.try_set(slice, &data)?;

        // For public data, set keys.
        let public = slice.to_range() & self.view.visibility().public();
        for range in public.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            let data = self.data_store.try_get(slice)?;
            self.key_store.try_set_public(slice, data)?;
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

impl ViewTrait<Binary> for VerifierStore {
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
#[error("verifier store error: {0}")]
pub struct VerifierStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("key store error: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("data store error: {0}")]
    Store(#[from] StoreError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    View(#[from] ViewError),
    #[error("wrong key count: expected {expected}, got {actual}")]
    WrongKeyCount { expected: usize, actual: usize },
    #[error("store was not expecting a flush")]
    UnexpectedFlush,
    #[error("prover flush view mismatch: expected {expected:?}, got {actual:?}")]
    Flush {
        expected: FlushView,
        actual: FlushView,
    },
}

impl From<KeyStoreError> for VerifierStoreError {
    fn from(err: KeyStoreError) -> Self {
        Self(ErrorRepr::KeyStore(err))
    }
}

impl From<StoreError> for VerifierStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for VerifierStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

impl From<ViewError> for VerifierStoreError {
    fn from(err: ViewError) -> Self {
        Self(ErrorRepr::View(err))
    }
}
