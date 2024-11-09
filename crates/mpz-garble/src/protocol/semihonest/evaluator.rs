use std::sync::Arc;

use async_trait::async_trait;
use hashbrown::HashMap;
use tokio::sync::Mutex;
use utils::{
    filter_drain::FilterDrain,
    range::{Disjoint, RangeSet},
};

<<<<<<< HEAD
use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
use mpz_garble_core::{EvaluatorOutput, GarbledCircuit, evaluate_garbled_circuits};
use mpz_memory_core::{DecodeFuture, Memory, Slice, View, binary::Binary};
use mpz_ot::cot::COTReceiver;
use mpz_vm_core::{Call, Callable, Execute, Result, VmError};

use crate::{evaluator::receive_garbled_circuit, store::EvaluatorStore};
=======
use mpz_common::{
    scoped_futures::{ScopedBoxFuture, ScopedFutureExt},
    Context, Flush,
};
use mpz_core::{bitvec::BitVec, Block};
use mpz_garble_core::{evaluate_garbled_circuits, EvaluatorOutput, GarbledCircuit};
use mpz_memory_core::{binary::Binary, DecodeFuture, Memory, Slice, View};
use mpz_ot::cot::COTReceiver;
use mpz_vm_core::{Call, Execute, Vm};

use crate::{
    evaluator::receive_garbled_circuit,
    store::{EvaluatorStore, EvaluatorStoreError},
};

type Result<T, E = EvaluatorError> = core::result::Result<T, E>;
type Error = EvaluatorError;
>>>>>>> 50828d7 (feat: garble vm (#191))

/// Semi-honest evaluator.
#[derive(Debug)]
pub struct Evaluator<COT> {
    store: Arc<Mutex<EvaluatorStore<COT>>>,
    call_stack: Vec<(Call, Slice)>,
    preprocessed: HashMap<Slice, (Call, GarbledCircuit)>,
}

impl<COT> Evaluator<COT> {
    /// Creates a new evaluator.
    pub fn new(cot: COT) -> Self {
        Self {
            store: Arc::new(Mutex::new(EvaluatorStore::new(cot))),
            call_stack: Vec::new(),
            preprocessed: HashMap::new(),
        }
    }

    fn take_preprocess_calls(&mut self) -> Vec<(Call, Slice)> {
        let mut idx_outputs = RangeSet::default();
        self.call_stack
            // Extract calls which have no dependencies on other prior calls.
            .filter_drain(|(call, output)| {
                if call
                    .inputs()
                    .iter()
                    .all(|input| input.to_range().is_disjoint(&idx_outputs))
                {
                    idx_outputs |= output.to_range();
                    true
                } else {
<<<<<<< HEAD
                    idx_outputs |= output.to_range();
=======
>>>>>>> 50828d7 (feat: garble vm (#191))
                    false
                }
            })
            .collect()
    }

    fn take_execute_calls(&mut self) -> Vec<(Call, Slice)> {
        let store = self.store.try_lock().unwrap();
        self.call_stack
            // Extract calls which have no dependencies on other prior calls.
            .filter_drain(|(call, _)| call.inputs().iter().all(|input| store.is_committed(*input)))
            .collect()
    }

    fn execute_preprocessed(&mut self) -> Result<()> {
        let mut store = self.store.try_lock().unwrap();
<<<<<<< HEAD
        loop {
            let (calls, outputs): (Vec<_>, Vec<_>) = self
                .preprocessed
                .extract_if(|_, (call, _)| {
                    call.inputs().iter().all(|input| store.is_committed(*input))
                })
                .map(|(output, (call, garbled_circuit))| {
                    let (circ, inputs) = call.into_parts();
                    let mut input_macs = Vec::with_capacity(circ.inputs().len());
                    for input in inputs {
                        input_macs.extend_from_slice(
                            store
                                .try_get_macs(input)
                                .expect("committed MACs should be set"),
                        );
                    }

                    ((circ, input_macs, garbled_circuit), output)
                })
                .unzip();

            if calls.is_empty() {
                break;
            }

            for (
                EvaluatorOutput {
                    outputs: output_macs,
                },
                output,
            ) in evaluate_garbled_circuits(calls)
                .map_err(VmError::execute)?
                .into_iter()
                .zip(outputs)
            {
                store
                    .set_output(output, &output_macs)
                    .map_err(VmError::memory)?;
            }

            store.flush_decode().map_err(VmError::memory)?;
        }

=======
        let (calls, outputs): (Vec<_>, Vec<_>) = self
            .preprocessed
            .extract_if(|_, (call, _)| call.inputs().iter().all(|input| store.is_committed(*input)))
            .map(|(output, (call, garbled_circuit))| {
                let (circ, inputs) = call.into_parts();
                let mut input_macs = Vec::with_capacity(circ.input_len());
                for input in inputs {
                    input_macs.extend_from_slice(
                        store
                            .try_get_macs(input)
                            .expect("committed MACs should be set"),
                    );
                }

                ((circ, input_macs, garbled_circuit), output)
            })
            .unzip();

        for (
            EvaluatorOutput {
                outputs: output_macs,
            },
            output,
        ) in evaluate_garbled_circuits(calls)
            .map_err(crate::evaluator::EvaluatorError::from)?
            .into_iter()
            .zip(outputs)
        {
            store.set_output(output, &output_macs)?;
        }

        store.flush_decode()?;

>>>>>>> 50828d7 (feat: garble vm (#191))
        Ok(())
    }
}

impl<COT> Memory<Binary> for Evaluator<COT> {
<<<<<<< HEAD
    type Error = VmError;
=======
    type Error = Error;
>>>>>>> 50828d7 (feat: garble vm (#191))

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store
            .try_lock()
            .unwrap()
            .alloc_raw(size)
<<<<<<< HEAD
            .map_err(VmError::memory)
=======
            .map_err(Error::from)
>>>>>>> 50828d7 (feat: garble vm (#191))
    }

    fn assign_raw(&mut self, slice: Slice, value: BitVec) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .assign_raw(slice, value)
<<<<<<< HEAD
            .map_err(VmError::memory)
=======
            .map_err(Error::from)
>>>>>>> 50828d7 (feat: garble vm (#191))
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .commit_raw(slice)
<<<<<<< HEAD
            .map_err(VmError::memory)
=======
            .map_err(Error::from)
>>>>>>> 50828d7 (feat: garble vm (#191))
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.store
            .try_lock()
            .unwrap()
            .get_raw(slice)
<<<<<<< HEAD
            .map_err(VmError::memory)
=======
            .map_err(Error::from)
>>>>>>> 50828d7 (feat: garble vm (#191))
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store
            .try_lock()
            .unwrap()
            .decode_raw(slice)
<<<<<<< HEAD
            .map_err(VmError::memory)
=======
            .map_err(Error::from)
>>>>>>> 50828d7 (feat: garble vm (#191))
    }
}

impl<COT> View<Binary> for Evaluator<COT>
where
    COT: COTReceiver<bool, Block>,
{
<<<<<<< HEAD
    type Error = VmError;
=======
    type Error = Error;
>>>>>>> 50828d7 (feat: garble vm (#191))

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_public_raw(slice)
<<<<<<< HEAD
            .map_err(VmError::view)
=======
            .map_err(Error::from)
>>>>>>> 50828d7 (feat: garble vm (#191))
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_private_raw(slice)
<<<<<<< HEAD
            .map_err(VmError::view)
=======
            .map_err(Error::from)
>>>>>>> 50828d7 (feat: garble vm (#191))
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store
            .try_lock()
            .unwrap()
            .mark_blind_raw(slice)
<<<<<<< HEAD
            .map_err(VmError::view)
    }
}

impl<COT> Callable<Binary> for Evaluator<COT> {
    fn call_raw(&mut self, call: Call) -> Result<Slice> {
=======
            .map_err(Error::from)
    }
}

impl<COT> Vm<Binary> for Evaluator<COT> {
    type Error = Error;

    fn call_raw(&mut self, call: Call) -> std::result::Result<Slice, <Self as Vm<Binary>>::Error> {
>>>>>>> 50828d7 (feat: garble vm (#191))
        let output = self
            .store
            .try_lock()
            .unwrap()
<<<<<<< HEAD
            .alloc_output(call.circ().outputs().len());
=======
            .alloc_output(call.circ().output_len());
>>>>>>> 50828d7 (feat: garble vm (#191))
        self.call_stack.push((call, output));
        Ok(output)
    }
}

#[async_trait]
<<<<<<< HEAD
impl<COT> Execute for Evaluator<COT>
where
    COT: COTReceiver<bool, Block> + Flush + Send + 'static,
    COT::Future: Send + 'static,
{
    fn wants_flush(&self) -> bool {
        self.store.try_lock().unwrap().wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<()> {
        let mut store = self.store.try_lock().unwrap();
        if store.wants_flush() {
            store.flush(ctx).await.map_err(VmError::memory)?;
=======
impl<Ctx, COT> Execute<Ctx> for Evaluator<COT>
where
    Ctx: Context + 'static,
    COT: COTReceiver<bool, Block> + Flush<Ctx> + Send + 'static,
    COT::Future: Send + 'static,
{
    type Error = Error;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<()> {
        let mut store = self.store.try_lock().unwrap();
        if store.wants_flush() {
            store.flush(ctx).await?;
>>>>>>> 50828d7 (feat: garble vm (#191))
        }

        Ok(())
    }

<<<<<<< HEAD
    fn wants_preprocess(&self) -> bool {
        let mut idx_outputs = RangeSet::default();
        self.call_stack.iter().any(|(call, output)| {
            let ready = call
                .inputs()
                .iter()
                .all(|input| input.to_range().is_disjoint(&idx_outputs));
            idx_outputs |= output.to_range();
            ready
        })
    }

    async fn preprocess(&mut self, ctx: &mut Context) -> Result<()> {
=======
    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<()> {
        let f = scope_closure(|ctx, (call, output): (Call, Slice)| {
            async move {
                let garbled_circuit = receive_garbled_circuit(ctx, call.circ()).await?;
                Ok::<_, Error>((call, output, garbled_circuit))
            }
            .scope_boxed()
        });

>>>>>>> 50828d7 (feat: garble vm (#191))
        while !self.call_stack.is_empty() {
            let calls = self.take_preprocess_calls();

            if calls.is_empty() {
                break;
            }

            let outputs = ctx
<<<<<<< HEAD
                .map(
                    calls,
                    async move |ctx, (call, output): (Call, Slice)| {
                        let garbled_circuit = receive_garbled_circuit(ctx, call.circ())
                            .await
                            .map_err(VmError::execute)?;
                        Ok::<_, VmError>((call, output, garbled_circuit))
                    },
                    |(call, _)| call.circ().and_count(),
                )
                .await
                .map_err(VmError::execute)?;
=======
                .map(calls, f, |(call, _)| call.circ().and_count())
                .await?;
>>>>>>> 50828d7 (feat: garble vm (#191))

            let mut store = self.store.try_lock().unwrap();
            for output in outputs {
                let (call, output, garbled_circuit) = output?;

                self.preprocessed.insert(output, (call, garbled_circuit));
<<<<<<< HEAD
                store
                    .mark_output_preprocessed(output)
                    .map_err(VmError::memory)?;
=======
                store.mark_output_preprocessed(output)?;
>>>>>>> 50828d7 (feat: garble vm (#191))
            }
        }

        Ok(())
    }

<<<<<<< HEAD
    fn wants_execute(&self) -> bool {
        let store = self.store.try_lock().unwrap();
        self.preprocessed
            .iter()
            .any(|(_, (call, _))| call.inputs().iter().all(|input| store.is_committed(*input)))
            || self
                .call_stack
                .iter()
                .any(|(call, _)| call.inputs().iter().all(|input| store.is_committed(*input)))
    }

    async fn execute(&mut self, ctx: &mut Context) -> Result<()> {
=======
    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()> {
>>>>>>> 50828d7 (feat: garble vm (#191))
        if !self.preprocessed.is_empty() {
            self.execute_preprocessed()?;
        }

<<<<<<< HEAD
=======
        let store = self.store.clone();
        let f = scope_closure(move |ctx, (call, output): (Call, Slice)| {
            evaluate(ctx, store.clone(), call, output).scope_boxed()
        });

>>>>>>> 50828d7 (feat: garble vm (#191))
        while !self.call_stack.is_empty() {
            let calls = self.take_execute_calls();

            if calls.is_empty() {
                break;
            }

<<<<<<< HEAD
            let store = self.store.clone();
            let outputs = ctx
                .map(
                    calls,
                    async move |ctx, (call, output): (Call, Slice)| {
                        evaluate(ctx, store.clone(), call, output).await
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
=======
            let outputs = ctx
                .map(calls, f.clone(), |(call, _)| call.circ().and_count())
                .await?;

            outputs.into_iter().collect::<Result<(), Error>>()?;
        }

        self.store.try_lock().unwrap().flush_decode()?;
>>>>>>> 50828d7 (feat: garble vm (#191))

        Ok(())
    }
}

<<<<<<< HEAD
async fn evaluate<COT>(
    ctx: &mut Context,
=======
// This is required to help the compiler infer the correct lifetimes.
fn scope_closure<Ctx, F, R>(f: F) -> F
where
    F: for<'a> Fn(&'a mut Ctx, (Call, Slice)) -> ScopedBoxFuture<'static, 'a, Result<R, Error>>
        + Clone
        + Send
        + 'static,
{
    f
}

async fn evaluate<Ctx: Context, COT>(
    ctx: &mut Ctx,
>>>>>>> 50828d7 (feat: garble vm (#191))
    store: Arc<Mutex<EvaluatorStore<COT>>>,
    call: Call,
    output: Slice,
) -> Result<()> {
    let (circ, inputs) = call.into_parts();

<<<<<<< HEAD
    let mut input_macs = Vec::with_capacity(circ.inputs().len());
    {
        let lock = store.lock().await;
        for input in inputs {
            input_macs.extend_from_slice(lock.try_get_macs(input).map_err(VmError::memory)?);
=======
    let mut input_macs = Vec::with_capacity(circ.input_len());
    {
        let lock = store.lock().await;
        for input in inputs {
            input_macs.extend_from_slice(lock.try_get_macs(input)?);
>>>>>>> 50828d7 (feat: garble vm (#191))
        }
    }

    let EvaluatorOutput {
        outputs: output_macs,
<<<<<<< HEAD
    } = crate::evaluator::evaluate(ctx, circ, &input_macs)
        .await
        .map_err(VmError::execute)?;

    let mut lock = store.lock().await;
    lock.set_output(output, &output_macs)
        .map_err(VmError::memory)?;

    Ok(())
}
=======
    } = crate::evaluator::evaluate(ctx, circ, input_macs).await?;

    let mut lock = store.lock().await;
    lock.set_output(output, &output_macs)?;

    Ok(())
}

/// Error for [`Evaluator`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct EvaluatorError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    Store(#[from] EvaluatorStoreError),
    #[error(transparent)]
    Evaluator(#[from] crate::evaluator::EvaluatorError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Context(#[from] mpz_common::ContextError),
}

impl From<EvaluatorStoreError> for EvaluatorError {
    fn from(value: EvaluatorStoreError) -> Self {
        EvaluatorError(ErrorRepr::Store(value))
    }
}

impl From<std::io::Error> for EvaluatorError {
    fn from(value: std::io::Error) -> Self {
        EvaluatorError(ErrorRepr::Io(value))
    }
}

impl From<mpz_common::ContextError> for EvaluatorError {
    fn from(value: mpz_common::ContextError) -> Self {
        EvaluatorError(ErrorRepr::Context(value))
    }
}

impl From<crate::evaluator::EvaluatorError> for EvaluatorError {
    fn from(value: crate::evaluator::EvaluatorError) -> Self {
        EvaluatorError(ErrorRepr::Evaluator(value))
    }
}
>>>>>>> 50828d7 (feat: garble vm (#191))
