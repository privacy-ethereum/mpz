use rand::Rng;

use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

use mpz_common::future::Output;
use mpz_core::{bitvec::{BitVec, BitSlice}, Block, prg::Prg};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Key, Delta, Mac, MacCommitment, MacCommitmentError, MacStore, MacStoreError, COMMIT_CIPHER, AuthBitStore, AuthBitStoreError},
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
    view::{AuthFlushView, AuthView, ViewError},
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
    view: AuthView,
    buffer_decode: Vec<DecodeOp<BitVec>>,
    pending: bool,
    pending_flush: Option<PendingFlush>,
}

impl<S, R> AuthEvalStore<S, R> {
    /// Creates a new evaluator store.
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
            view: AuthView::new_evaluator(),
            buffer_decode: Vec::default(),
            pending: false,
            pending_flush: None,
        }
    }

    /// Returns the delta of the eval store.
    pub fn delta(&self) -> &Delta {
        self.mask_store.delta()
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

    /// Returns the masked values for a slice.
    pub fn try_get_masked_values(&self, slice: Slice) -> Result<&BitSlice> {
        self.masked_value_store.try_get(slice).map_err(Error::from)
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
    pub fn set_output(&mut self, slice: Slice, macs: &[Mac], mask_bits: &BitSlice, mask_macs: &[Mac], mask_keys: &[Key], masked_values: &BitSlice) -> Result<()> {
        self.view.set_output(slice.to_range())?;
        self.mac_store.try_set(slice, macs)?;
        self.mask_store.try_set_bits(slice, mask_bits)?;
        self.mask_store.try_set_macs(slice, mask_macs)?;
        self.mask_store.try_set_keys(slice, mask_keys)?;
        self.masked_value_store.try_set(slice, masked_values)?;
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
    fn _decode_macs(&mut self) -> Result<()> {
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
        if self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let view = self.view.flush().clone();

        // Send OT keys for masks.
        let masks = view.gen_masks.clone() | view.eval_masks.clone();
        if !masks.is_empty() {
            let keys = (0..masks.len()).map(|_| self.prg.random()).collect::<Vec<_>>();
            // Store keys in mask store.
            for range in masks.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.mask_store.try_set_keys(slice, &keys)?;
            }
            // Queue COT, we don't need the output here.
            _ = self
                .cot_sender
                .try_lock()
                .unwrap()
                .queue_send_cot(Key::as_blocks(&keys))
                .map_err(Error::cot)?;
        }

        // Send OT choices for masks, box the output to receive Macs as a future.
        let cot = if !masks.is_empty() {
            // Collect the choices for oblivious transfer.
            let choices: Vec<bool> = (0..masks.len()).map(|_| self.prg.random()).collect::<Vec<_>>();
            for range in masks.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.mask_store.try_set_bits(slice, &BitVec::from_iter(choices.iter()))?;
            }
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

        // Prove Eval's share of Gen input wires
        let share_proof = if !view.gen_reveal.is_empty() {
            let (bits, macs) = self.mask_store.prove_share(&view.gen_reveal)?;
            // Set masked_value_store using sent bits
            let mut i = 0;
            for range in view.gen_reveal.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.masked_value_store
                    .try_set(slice, &bits[i..i + slice.len()])?;
                i += slice.len();
            }

            Some(ShareProof { bits, macs })
        } else {
            None
        };

        // Send half masked inputs corresponding to Eval's input wires. 
        let mut half_masked_inputs = BitVec::with_capacity(view.eval_reveal.len());
        for range in view.eval_reveal.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let mask_bits = self.mask_store.try_get_bits(slice)?;
            let data_bits = self.data_store.try_get(slice)?;
            
            // might be a cleaner way to do this
            let mut half_masked = mask_bits.to_bitvec();
            for (mut half_masked_bit, data_bit) in half_masked.iter_mut().zip(data_bits) {
                *half_masked_bit ^= *data_bit;
            }
            
            self.masked_value_store.try_set(slice, &half_masked)?;
            half_masked_inputs.extend_from_bitslice(&half_masked);
        }

        // Prove Eval's share of Eval's input wires for decoding.
        let decode_share_proof = if !view.eval_decode_info.is_empty() {
            let (bits, macs) = self.mask_store.prove_share(&view.eval_decode_info)?;

            Some(ShareProof { bits, macs })
        } else {
            None
        };

        let flush = AuthEvalFlush {
            view,
            share_proof,
            half_masked_inputs,
            decode_share_proof,
        };

        self.pending = true;
        self.pending_flush = Some(PendingFlush { cot });

        Ok(flush)
    }

    /// Receives flush from the generator.
    ///
    /// This expects that the COT receiver has been flushed.
    pub fn receive_flush(&mut self, flush: AuthGenFlush) -> Result<()> {
        if !self.pending {
            return Err(ErrorRepr::UnexpectedFlush.into());
        }

        let Some(PendingFlush { cot }) = self.pending_flush.take() else {
            return Err(ErrorRepr::UnexpectedFlush.into());
        };

        let AuthGenFlush { 
            view, 
            share_proof, 
            half_masked_inputs, 
            labels,
            decode_share_proof,
        } = flush;

        if &view != self.view.flush() {
            return Err(ErrorRepr::InconsistentFlush {
                expected: self.view.flush().clone(),
                actual: view,
            }.into());
        }

        // Receive OT macs for masks, expects COT to be flushed.
        let masks = view.gen_masks.clone() | view.eval_masks.clone();
        let mut i = 0;
        if let Some(mut cot) = cot {
            let COTReceiverOutput { msgs: macs, .. } = cot
                .try_recv()
                .map_err(Error::cot)?
                .ok_or_else(|| Error::cot("COT output is not ready"))?;
            let macs = Mac::from_blocks(macs);
            for range in masks.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.mask_store.try_set_macs(slice, &macs[i..i + slice.len()])?;
                i += slice.len();
            }
        }

        // Check Gen's share of Eval input wires
        if let Some(ShareProof { bits, macs }) = share_proof {
            
            // if !view.eval_reveal.is_empty() {
            //     let mut keys: Vec<Key> = Vec::new();
            //     for range in view.eval_reveal.iter_ranges() {
            //         let slice = Slice::from_range_unchecked(range);
            //         let key = self.mask_store.try_get_keys(slice)?;
            //         keys.extend(key);
            //     }

            //     for (mac, key) in macs.iter().zip(keys) {
            //         println!("Received MAC: {:?}, Key: {:?}", mac, key);
            //     }
            // }
            
            self.mask_store.check_share(&view.eval_reveal, &bits, &macs)?;            
            // Update masked values of eval's input wires with share proof bits
            let mut i = 0;
            for range in view.eval_reveal.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.masked_value_store.update_xor(slice, &bits[i..i + slice.len()])?;
                i += slice.len();
            }
        }

        // Update masked values with gen's half masked inputs
        i = 0;
        for range in view.gen_reveal.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.masked_value_store.update_xor(slice, &half_masked_inputs[i..i + slice.len()])?;
            i += slice.len();
        }

        // Store MAC labels
        let mut i = 0;
        for range in view.labels.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.mac_store.try_set(slice, &labels[i..i + slice.len()])?;
            i += slice.len();
        }

        if let Some(ShareProof { bits, macs }) = decode_share_proof {
            self.mask_store.check_share(&view.gen_decode_info, &bits, &macs)?;

            // Decode gen's input wires.
            let mut i = 0;
            for range in view.gen_decode_info.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.data_store.try_set(slice, &bits[i..i + slice.len()])?;
                self.data_store.update_xor(slice, self.masked_value_store.try_get(slice)?)?;
                self.data_store.update_xor(slice, self.mask_store.try_get_bits(slice)?)?;
                i += slice.len();
            }
        }
        println!("Eval's complete flush");
        self.view.complete_flush(view);
        self.flush_decode()?;
        self.pending = false;
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
        self.masked_value_store.alloc(size);
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
        // Allocate both sender and receiver COTs for private data.
        self.cot_sender
            .try_lock()
            .unwrap()
            .alloc(slice.len())
            .map_err(Error::cot)?;

        self.cot_receiver
            .try_lock()
            .unwrap()
            .alloc(slice.len())
            .map_err(Error::cot)?;

        self.view.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        // Allocate both sender and receiver COTs for blind data.
        self.cot_sender
            .try_lock()
            .unwrap()
            .alloc(slice.len())
            .map_err(Error::cot)?;

        self.cot_receiver
            .try_lock()
            .unwrap()
            .alloc(slice.len())
            .map_err(Error::cot)?;

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
        expected: AuthFlushView,
        actual: AuthFlushView,
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
