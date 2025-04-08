use rand::Rng;
use core::num;
use std::sync::Arc;

use async_trait::async_trait;
use hashbrown::HashMap;
use tokio::sync::Mutex;
use utils::{
    filter_drain::FilterDrain,
    range::{Disjoint, RangeSet},
};
use mpz_common::future::Output;

use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec, prg::Prg};
use mpz_garble_core::{AuthEvalOutput, AuthGarbledCircuit, evaluate_garbled_circuits, fpre::AuthBitShare, SSP};
use mpz_memory_core::{DecodeFuture, Memory, Slice, View, binary::Binary, correlated::{Delta, Key, Mac}};
use mpz_ot::cot::{COTReceiver, COTSender};
use mpz_vm_core::{Call, Callable, Execute, Result, VmError};
use mpz_ot::cot::COTReceiverOutput;

use serio::{SinkExt, stream::IoStreamExt};

use crate::{auth_eval::receive_garbled_circuit, store::AuthEvalStore};

/// Semi-honest evaluator.
#[derive(Debug)]
pub struct AuthEval<S, R> {
    store: Arc<Mutex<AuthEvalStore<S, R>>>,
    call_stack: Vec<(Call, Slice)>,
    // preprocessed: HashMap<Slice, (Call, AuthGarbledCircuit)>,
    prg: Prg,
}

impl<S, R> AuthEval<S, R> 
    {
        /// Creates a new evaluator.
        pub fn new(seed: [u8; 16], delta: Delta, cot_sender: S, cot_receiver: R) -> Self {
            Self {
            store: Arc::new(Mutex::new(AuthEvalStore::new(seed, delta, cot_sender, cot_receiver))),
            call_stack: Vec::new(),
            prg: Prg::new_with_seed(seed),
            // preprocessed: HashMap::new(),
        }
    }

    // Should I move COT generation to a new function here? And then store the COTs in the call_stack...

    // fn take_preprocess_calls(&mut self) -> Vec<(Call, Slice)> {
    //     let mut idx_outputs = RangeSet::default();
    //     self.call_stack
    //         // Extract calls which have no dependencies on other prior calls.
    //         .filter_drain(|(call, output)| {
    //             if call
    //                 .inputs()
    //                 .iter()
    //                 .all(|input| input.to_range().is_disjoint(&idx_outputs))
    //             {
    //                 idx_outputs |= output.to_range();
    //                 true
    //             } else {
    //                 idx_outputs |= output.to_range();
    //                 false
    //             }
    //         })
    //         .collect()
    // }

    fn take_execute_calls(&mut self) -> Vec<(Call, Slice)> {
        let store = self.store.try_lock().unwrap();
        self.call_stack
            // Extract calls which have no dependencies on other prior calls.
            .filter_drain(|(call, _)| call.inputs().iter().all(|input| store.is_committed(*input)))
            .collect()
    }

    // fn execute_preprocessed(&mut self) -> Result<()> {
    //     let mut store = self.store.try_lock().unwrap();
    //     loop {
    //         let (calls, outputs): (Vec<_>, Vec<_>) = self
    //             .preprocessed
    //             .extract_if(|_, (call, _)| {
    //                 call.inputs().iter().all(|input| store.is_committed(*input))
    //             })
    //             .map(|(output, (call, garbled_circuit))| {
    //                 let (circ, inputs) = call.into_parts();
    //                 let mut input_macs = Vec::with_capacity(circ.inputs().len());
    //                 for input in inputs {
    //                     input_macs.extend_from_slice(
    //                         store
    //                             .try_get_macs(input)
    //                             .expect("committed MACs should be set"),
    //                     );
    //                 }

    //                 ((circ, input_macs, garbled_circuit), output)
    //             })
    //             .unzip();

    //         if calls.is_empty() {
    //             break;
    //         }

    //         for (
    //             EvaluatorOutput {
    //                 outputs: output_macs,
    //             },
    //             output,
    //         ) in evaluate_garbled_circuits(calls)
    //             .map_err(VmError::execute)?
    //             .into_iter()
    //             .zip(outputs)
    //         {
    //             store
    //                 .set_output(output, &output_macs)
    //                 .map_err(VmError::memory)?;
    //         }

    //         store.flush_decode().map_err(VmError::memory)?;
    //     }

    //     Ok(())
    // }
}

impl<S, R> Memory<Binary> for AuthEval<S, R>
where
{
    type Error = VmError;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store
            .try_lock()
            .unwrap()
            .alloc_raw(size)
            .map_err(VmError::memory)
    }

    fn assign_raw(&mut self, slice: Slice, value: BitVec) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .assign_raw(slice, value)
            .map_err(VmError::memory)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .commit_raw(slice)
            .map_err(VmError::memory)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.store
            .try_lock()
            .unwrap()
            .get_raw(slice)
            .map_err(VmError::memory)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store
            .try_lock()
            .unwrap()
            .decode_raw(slice)
            .map_err(VmError::memory)
    }
}

impl<S, R> View<Binary> for AuthEval<S, R>
where
    S: COTSender<Block>,
    R: COTReceiver<bool, Block>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_public_raw(slice)
            .map_err(VmError::view)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_private_raw(slice)
            .map_err(VmError::view)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_blind_raw(slice)
            .map_err(VmError::view)
    }
}

impl<S, R> Callable<Binary> for AuthEval<S, R>
where
    S: COTSender<Block>,
    R: COTReceiver<bool, Block> + Flush + Send + 'static,
    R::Future: Send + 'static,
{
    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let mut store = self.store.try_lock().unwrap();
        let output = store.alloc_output(call.circ().outputs().len());
        let mut cot_sender = store.acquire_cot_sender();
        let mut cot_receiver = store.acquire_cot_receiver();

        let bucket_size = (SSP as f64 / (call.circ().and_count() as f64).log2()).ceil() as usize;
        let num_and_shares = call.circ().and_count()*(3*bucket_size+1);

        // need a better way to handle this error
        cot_sender.alloc(num_and_shares).unwrap();
        cot_receiver.alloc(num_and_shares).unwrap();

        self.call_stack.push((call, output));
        Ok(output)
    }
}

#[async_trait]
impl<S, R> Execute for AuthEval<S, R>
where
    S: COTSender<Block> + Flush + Send + 'static,
    R: COTReceiver<bool, Block> + Flush + Send + 'static,
    R::Future: Send + 'static,
{
    fn wants_flush(&self) -> bool {
        self.store.try_lock().unwrap().wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<()> {
        let mut store = self.store.try_lock().unwrap();
        if store.wants_flush() {
            store.flush(ctx).await.map_err(VmError::memory)?;
        }

        Ok(())
    }

    fn wants_preprocess(&self) -> bool {
        // let mut idx_outputs = RangeSet::default();
        // self.call_stack.iter().any(|(call, output)| {
        //     let ready = call
        //         .inputs()
        //         .iter()
        //         .all(|input| input.to_range().is_disjoint(&idx_outputs));
        //     idx_outputs |= output.to_range();
        //     ready
        // })
        unimplemented!()
    }

    async fn preprocess(&mut self, ctx: &mut Context) -> Result<()> {
        // while !self.call_stack.is_empty() {
        //     let calls = self.take_preprocess_calls();

        //     if calls.is_empty() {
        //         break;
        //     }

        //     let outputs = ctx
        //         .map(
        //             calls,
        //             async move |ctx, (call, output): (Call, Slice)| {
        //                 let garbled_circuit = receive_garbled_circuit(ctx, call.circ())
        //                     .await
        //                     .map_err(VmError::execute)?;
        //                 Ok::<_, VmError>((call, output, garbled_circuit))
        //             },
        //             |(call, _)| call.circ().and_count(),
        //         )
        //         .await
        //         .map_err(VmError::execute)?;

        //     let mut store = self.store.try_lock().unwrap();
        //     for output in outputs {
        //         let (call, output, garbled_circuit) = output?;

        //         self.preprocessed.insert(output, (call, garbled_circuit));
        //         store
        //             .mark_output_preprocessed(output)
        //             .map_err(VmError::memory)?;
        //     }
        // }

        // Ok(())
        unimplemented!()
    }

    fn wants_execute(&self) -> bool {
        let store = self.store.try_lock().unwrap();
        // self.preprocessed
        //     .iter()
        //     .any(|(_, (call, _))| call.inputs().iter().all(|input| store.is_committed(*input)))
        //     || 
                self.call_stack
                .iter()
                .any(|(call, _)| call.inputs().iter().all(|input| store.is_committed(*input)))
    }

    async fn execute(&mut self, ctx: &mut Context) -> Result<()> {
        // if !self.preprocessed.is_empty() {
        //     self.execute_preprocessed()?;
        // }

        let delta = *self.store.try_lock().unwrap().delta();

        while !self.call_stack.is_empty() {
            let calls = self.take_execute_calls();

            if calls.is_empty() {
                break;
            }

            let store = self.store.clone();
            let prg = self.prg.clone();
            let outputs = ctx
                .map(
                    calls,
                    async move |ctx, (call, output): (Call, Slice)| {
                        evaluate(ctx, store.clone(), delta, call, output, prg.clone()).await
                    },
                    |(call, _)| call.circ().and_count(),
                )
                .await
                .map_err(VmError::execute)?;

            outputs.into_iter().collect::<Result<()>>()?;
        }

        self.store
            .try_lock()
            .unwrap()
            .flush_decode()
            .map_err(VmError::memory)?;

        Ok(())
    }
}

async fn evaluate<S,R>(
    ctx: &mut Context,
    store: Arc<Mutex<AuthEvalStore<S, R>>>,
    delta: Delta,
    call: Call,
    output: Slice,
    mut prg: Prg,
) -> Result<()> 
where
    S: COTSender<Block> + Flush + Send + 'static,
    R: COTReceiver<bool, Block> + Flush + Send + 'static,
{
    let (circ, inputs) = call.into_parts();

    let mut input_macs = Vec::with_capacity(circ.inputs().len());
    let mut input_masked_values = Vec::with_capacity(circ.inputs().len());
    let mut input_auth_bits = Vec::with_capacity(circ.inputs().len());
    {
        let lock = store.lock().await;
        for input in inputs {
            input_macs.extend_from_slice(lock.try_get_macs(input).map_err(VmError::memory)?);
            // TODO: This is a hack, we should not be converting to a bitvec
            let masked_values = lock.try_get_masked_values(input).map_err(VmError::memory)?.to_bitvec();
            input_masked_values.extend(masked_values);
            let mask_bits = lock.try_get_mask_bits(input).map_err(VmError::memory)?;
            let mask_macs = lock.try_get_mask_macs(input).map_err(VmError::memory)?;
            let mask_keys = lock.try_get_mask_keys(input).map_err(VmError::memory)?;
            
            for ((value, mac), key) in mask_bits.iter().zip(mask_macs).zip(mask_keys) {
                input_auth_bits.push(AuthBitShare {
                    value: *value,
                    mac: *mac,
                    key: *key,
                });
            }
        }
    }

    // obtain COTs required for AND gates
    let bucket_size = (SSP as f64 / (circ.and_count() as f64).log2()).ceil() as usize;
    let num_and_shares = circ.and_count()*(3*bucket_size+1);

    // let mut cot_receiver = store.try_lock().unwrap().acquire_cot_receiver();

    // println!("eval reached here");
    
    // let choices: Vec<bool> = (0..num_and_shares).map(|_| prg.random()).collect::<Vec<_>>();
    // let cot = {
    //     let output = cot_receiver
    //     .queue_recv_cot(&choices)
    //     // TODO: Handle error
    //     .unwrap();
    //     Some(Box::new(output) as Box<dyn Output<COTReceiverOutput<Block>> + Send>)
    // };

    // cot_receiver.flush(ctx).await.unwrap();

    // let mut cot_sender = store.try_lock().unwrap().acquire_cot_sender();

    // println!("eval reached here 2");

    // let keys: Vec<Key> = (0..num_and_shares).map(|_| prg.random()).collect::<Vec<_>>();
    // // Queue COT, we don't need the output here.
    // _ = cot_sender
    //     .queue_send_cot(Key::as_blocks(&keys))
    //     // TODO: Handle error
    //     .unwrap();  

    // cot_sender.flush(ctx).await.unwrap();
    
    let mut and_shares = Vec::with_capacity(num_and_shares);

    // if let Some(mut cot) = cot {
    //     if let Some(COTReceiverOutput { msgs: macs, .. }) = cot.try_recv().unwrap() {
    //         let macs = Mac::from_blocks(macs);
    //         for ((value, mac), key) in choices.iter().zip(macs).zip(keys) {
    //             and_shares.push(AuthBitShare {
    //                 value: *value,
    //                 mac,
    //                 key,
    //             });
    //         }
    //     }
    // }

    for _ in 0..num_and_shares {
        and_shares.push(AuthBitShare::default());
    }

    let AuthEvalOutput {
        output_labels,
        output_auth_bits,
        auth_hash,
        masked_output_values,
        masked_values: _masked_values,
    } = crate::auth_eval::evaluate(ctx, circ, delta,  &input_macs, input_masked_values, &input_auth_bits, &and_shares)
        .await
        .map_err(VmError::execute)?;

    let io = ctx.io_mut();
    let gen_hash: Block = io.expect_next().await?;

    // TODO: Handle error
    assert_eq!(gen_hash, auth_hash);

    let output_bits: Vec<_> = output_auth_bits.iter().map(|share| share.value).collect();
    let output_macs: Vec<_> = output_auth_bits.iter().map(|share| share.mac).collect();
    let output_keys: Vec<_> = output_auth_bits.iter().map(|share| share.key).collect();

    let output_bits = BitVec::from_iter(output_bits);
    let masked_output_values = BitVec::from_iter(masked_output_values);
    let mut lock = store.lock().await;
    lock.set_output(output, &output_labels, &output_bits, &output_macs, &output_keys, &masked_output_values)
        .map_err(VmError::memory)?;

    Ok(())
}
