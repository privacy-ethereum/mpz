use rand::Rng;

use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_common::future::Output;
use mpz_core::{bitvec::{BitVec, BitSlice}, Block, prg::Prg};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Key, Delta, Mac, MacCommitment, MacCommitmentError, MacStore, MacStoreError, COMMIT_CIPHER, AuthBitStore, AuthBit, AuthBitStoreError},
    store::{BitStore, Store, StoreError},
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use mpz_ot_core::cot::{COTReceiver, COTReceiverOutput, COTSender};
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Intersection},
};

use crate::{
    store::{ShareProof, AuthEvalFlush, AuthGenFlush},
    view::{FlushView, View, ViewError},
};

type Error = AuthEvalStoreError;
type Result<T> = core::result::Result<T, Error>;

struct PendingFlush {
    cot: Option<Box<dyn Output<COTReceiverOutput<Block>> + Send>>,
}

impl std::fmt::Debug for PendingFlush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingFlush").finish_non_exhaustive()
    }
}

/// Authenticated evaluator memory store.
#[derive(Debug)]
pub struct AuthEvalStore<S, R> {
    cot_sender: Arc<Mutex<S>>,
    cot_receiver: Arc<Mutex<R>>,
    prg: Prg,
    // I suspect we can remove mac_store since labels are used to authenticate masked data
    mac_store: MacStore,
    mask_store: AuthBitStore,
    masked_value_store: BitStore,
    // key bits and commitments aren't needed in auth garbling
    key_bit_store: BitStore,
    // TODO: We need a sparse store as this takes up a lot of space.
    commit_store: Store<MacCommitment>,
    data_store: BitStore,
    view: View,
    buffer_decode: Vec<DecodeOp<BitVec>>,
    pending: Option<PendingFlush>,
}

impl<S, R> AuthEvalStore<S, R>
{
    /// Creates a new evaluator store.
    ///
    /// # Argument
    ///
    /// * `cot_sender` - Correlated OT sender.
    /// * `cot_receiver` - Correlated OT receiver.
    pub fn new(seed: [u8; 16], delta: Delta, cot_sender: S, cot_receiver: R) -> Self {
        Self {
            cot_sender: Arc::new(Mutex::new(cot_sender)),
            cot_receiver: Arc::new(Mutex::new(cot_receiver)),
            prg: Prg::new_with_seed(seed),
            mac_store: MacStore::default(),
            mask_store: AuthBitStore::new(delta),
            masked_value_store: BitStore::default(),
            key_bit_store: BitStore::default(),
            commit_store: Store::default(),
            data_store: BitStore::default(),
            view: View::new_evaluator(),
            buffer_decode: Vec::default(),
            pending: None,
        }
    }

    /// Returns a lock on the COT sender.
    pub fn acquire_cot_sender(&self) -> OwnedMutexGuard<S> {
        Mutex::try_lock_owned(self.cot_sender.clone()).unwrap()
    }

    /// Returns a lock on the COT sender.
    pub fn acquire_cot_receiver(&self) -> OwnedMutexGuard<R> {
        Mutex::try_lock_owned(self.cot_receiver.clone()).unwrap()
    }

    /// Returns the COT sender.
    ///
    /// # Panics
    ///
    /// Panics if a lock to the sender is still held.
    pub fn into_inner_sender(self) -> S {
        Arc::try_unwrap(self.cot_sender)
            .map_err(|_| ())
            .expect("sender lock should be dropped")
            .into_inner()
    }

    /// Returns the COT receiver.
    ///
    /// # Panics
    ///
    /// Panics if a lock to the receiver is still held.
    pub fn into_inner_receiver(self) -> R {
        Arc::try_unwrap(self.cot_receiver)
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
        self.data_store.alloc(size);
        self.masked_value_store.alloc(size);
        self.mask_store.alloc(size)
    }

    /// Returns whether the MACs are set for a slice.
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        self.mac_store.is_set(slice)
    }

    /// Returns whether the masks are set for a slice.
    pub fn is_set_masks(&self, slice: Slice) -> bool {
        self.mask_store.is_set(slice)
    }

    /// Returns whether the slice is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        self.view.is_committed(slice.to_range())
    }

    /// Returns the MACs for a slice.
    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mac_store.try_get(slice).map_err(Error::from)
    }

    /// Returns the masks for a slice.
    pub fn try_get_mask_bits(&self, slice: Slice) -> Result<&BitSlice> {
        self.mask_store.try_get_bits(slice).map_err(Error::from)
    }

    /// Returns the masks for a slice.
    pub fn try_get_mask_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mask_store.try_get_macs(slice).map_err(Error::from)
    }

    /// Returns the masks for a slice.
    pub fn try_get_mask_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.mask_store.try_get_keys(slice).map_err(Error::from)
    }
    

    /// Sets the MACs for a slice corresponding to output.
    pub fn set_output(&mut self, slice: Slice, macs: &[Mac], mask_bits: &BitSlice, mask_macs: &[Mac], mask_keys: &[Key]) -> Result<()> {
        self.view.set_output(slice.to_range())?;
        self.mac_store.try_set(slice, macs)?;
        self.mask_store.try_set_bits(slice, mask_bits)?;
        self.mask_store.try_set_macs(slice, mask_macs)?;
        self.mask_store.try_set_keys(slice, mask_keys)?;

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
    // TODO: change this decoding to use masks and MACs.
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

impl<S, R> AuthEvalStore<S, R>
where
    S: COTSender<Block>,
    R: COTReceiver<bool, Block>,
    R::Future: Send + 'static,
{
    /// Sends a flush to the generator.
    ///
    /// This queues any necessary COTs.
    pub fn send_flush(&mut self) -> Result<AuthEvalFlush> {
        if self.pending.is_some() {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let view = self.view.flush().clone();

        // Send keys for OT.
        if !view.ot.is_empty() {
            let keys = (0..view.ot.len()).map(|_| self.prg.gen()).collect::<Vec<_>>();

            // Queue COT, we don't need the output here.
            _ = self
                .cot_sender
                .try_lock()
                .unwrap()
                .queue_send_cot(Key::as_blocks(&keys))
                .map_err(Error::cot)?;
        }

        let cot = if !view.ot.is_empty() {
            // Collect the choices for oblivious transfer.
            let choices: Vec<bool> = (0..view.ot.len()).map(|_| self.prg.gen()).collect::<Vec<_>>();

            let output = self
                .cot_receiver
                .try_lock()
                .unwrap()
                .queue_recv_cot(&choices)
                .map_err(Error::cot)?;
            Some(Box::new(output) as Box<dyn Output<COTReceiverOutput<Block>> + Send>)
        } else {
            None
        };

        self.pending = Some(PendingFlush { cot });

        // Prove Gen's share of Eval input wires. Change to correct view.
        let share_proof = if !view.macs.is_empty() {
            let (bits, macs) = self.mask_store.prove_share(&view.macs)?;

            Some(ShareProof { bits, macs })
        } else {
            None
        };

        let mut half_masked_inputs = Vec::with_capacity(view.ot.len());
        for range in view.ot.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let mask_bits = self.mask_store.try_get_bits(slice)?;
            let data_bits = self.data_store.try_get(slice)?;
            // XOR mask bits with data bits
            half_masked_inputs.extend(mask_bits.iter().zip(data_bits.iter()).map(|(m, d)| *m ^ *d));
        }

        let slice = Slice::from_range_unchecked(view.ot.iter_ranges().next().unwrap());
        self.masked_value_store.try_set(slice, &BitVec::from_iter(&half_masked_inputs))?;


        let flush = AuthEvalFlush {
            view,
            share_proof,
            half_masked_inputs,
        };

        Ok(flush)
    }

    /// Receives flush from the generator.
    ///
    /// This expects that the COT receiver has been flushed.
    pub fn receive_flush(&mut self, flush: AuthGenFlush) -> Result<()> {
        let Some(PendingFlush { cot }) = self.pending.take() else {
            return Err(ErrorRepr::UnexpectedFlush.into());
        };

        let AuthGenFlush { view, share_proof, half_masked_inputs, labels } = flush;

        // Handle COT section
        let mut i = 0;
        if let Some(mut cot) = cot {
            let COTReceiverOutput { msgs: macs, .. } = cot
                .try_recv()
                .map_err(Error::cot)?
                .ok_or_else(|| Error::cot("COT output is not ready"))?;
            let macs = Mac::from_blocks(macs);
            for range in view.ot.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.mask_store.try_set_macs(slice, &macs[i..i + slice.len()])?;
                i += slice.len();
            }
        }

        // Handle share proof and masked updates for view.ot
        let ShareProof { bits, macs } = share_proof.unwrap();
        self.mask_store.check_share(&view.ot, &bits, &macs)?;

        i = 0;
        for range in view.ot.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let current_masked = self.masked_value_store.try_get(slice)?;
            let mut final_masked = current_masked.to_bitvec();
            
            // XOR current masked values with bits from share proof
            for (mut bit, share_bit) in final_masked.iter_mut().zip(&bits[i..i + slice.len()]) {
                *bit ^= *share_bit;
            }
            
            self.masked_value_store.try_set(slice, &final_masked)?;
            i += slice.len();
        }

        // Handle masked updates for view.macs
        i = 0;
        for range in view.macs.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let mask_share = self.mask_store.try_get_bits(slice)?;
            
            let final_masked = BitVec::from_iter(
                mask_share.iter()
                    .zip(&half_masked_inputs[i..i + slice.len()])
                    .map(|(a, b)| *a ^ *b)
            );
            
            self.masked_value_store.try_set(slice, &final_masked)?;
            i += slice.len();
        }

        // Store MAC labels
        let mut i = 0;
        for range in view.macs.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.mac_store.try_set(slice, &labels[i..i + slice.len()])?;
            i += slice.len();
        }

        Ok(())
    }
}

impl<S, R> Memory<Binary> for AuthEvalStore<S, R>
{
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc_input(size);
        self.mac_store.alloc(size);
        self.commit_store.alloc(size);
        self.key_bit_store.alloc(size);
        self.mask_store.alloc(size);
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

impl<S, R> ViewTrait<Binary> for AuthEvalStore<S, R>
where
    S: COTSender<Block>,
    R: COTReceiver<bool, Block>,
{
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.view.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        // Allocate COTs for private data.
        self.cot_receiver
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
pub struct AuthEvalStoreError(#[from] ErrorRepr);

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
    #[error("cot error: {0}")]
    Cot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    MacStore(MacStoreError),
    #[error(transparent)]
    AuthBitStore(#[from] AuthBitStoreError),
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

impl From<MacStoreError> for AuthEvalStoreError {
    fn from(err: MacStoreError) -> Self {
        Self(ErrorRepr::MacStore(err))
    }
}

impl From<AuthBitStoreError> for AuthEvalStoreError {
    fn from(err: AuthBitStoreError) -> Self {
        Self(ErrorRepr::AuthBitStore(err))
    }
}

impl From<StoreError> for AuthEvalStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for AuthEvalStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

impl From<ViewError> for AuthEvalStoreError {
    fn from(err: ViewError) -> Self {
        Self(ErrorRepr::View(err))
    }
}

impl From<MacCommitmentError> for AuthEvalStoreError {
    fn from(err: MacCommitmentError) -> Self {
        Self(ErrorRepr::MacCommitment(err))
    }
}
