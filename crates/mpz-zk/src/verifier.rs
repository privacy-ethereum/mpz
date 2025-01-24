use async_trait::async_trait;
use mpz_common::{scoped_futures::ScopedFutureExt, Context, Flush};
use mpz_core::{bitvec::BitVec, Block};
use mpz_ot::rcot::{RCOTSender, RCOTSenderOutput};
use mpz_vm_core::{
    memory::{
        binary::Binary,
        correlated::{Delta, Key},
        DecodeFuture, Memory, Slice, View,
    },
    Call, Callable, Execute, Result, VmError,
};
use mpz_zk_core::{store::VerifierStore, Verifier as Core};
use serio::{stream::IoStreamExt, SinkExt};
use utils::filter_drain::FilterDrain;

#[derive(Debug)]
pub struct Verifier<OT> {
    store: VerifierStore,
    ot: OT,
    callstack: Vec<(Call, Slice)>,
}

impl<OT> Verifier<OT> {
    /// Creates a new prover.
    pub fn new(delta: Delta, ot: OT) -> Self {
        Self {
            store: VerifierStore::new(delta),
            ot,
            callstack: Vec::default(),
        }
    }
}

#[async_trait]
impl< OT> Execute for Verifier<OT>
where
    
    OT: RCOTSender<Block> + Flush + Send + 'static,
{
    async fn flush(&mut self, ctx: &mut Context) -> Result<()> {
        if self.ot.wants_flush() {
            self.ot.flush(ctx).await.map_err(VmError::execute)?;
        }

        if self.store.wants_keys() {
            let RCOTSenderOutput { keys, .. } = self
                .ot
                .try_send_rcot(self.store.key_count())
                .map_err(VmError::execute)?;
            let keys = Key::from_blocks(keys);

            self.store.set_keys(&keys).map_err(VmError::memory)?;
        }

        while self.store.wants_flush() {
            let flush = self.store.send_flush().map_err(VmError::memory)?;
            ctx.io_mut().send(flush).await?;
            let flush = ctx.io_mut().expect_next().await?;
            self.store.receive_flush(flush).map_err(VmError::memory)?;
        }

        Ok(())
    }

    async fn preprocess(&mut self, _ctx: &mut Context) -> Result<()> {
        Ok(())
    }

    async fn execute(&mut self, ctx: &mut Context) -> Result<()> {
        let mut verifier = Core::new(*self.store.delta());
        while !self.callstack.is_empty() {
            let ready_calls: Vec<_> = self
                .callstack
                .filter_drain(|(call, _)| {
                    call.inputs()
                        .iter()
                        .all(|input| self.store.is_committed(*input))
                })
                .map(|(call, output)| {
                    let input_keys = call
                        .inputs()
                        .iter()
                        .flat_map(|input| {
                            self.store.try_get_keys(*input).expect("keys should be set")
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    let (circ, _) = call.into_parts();
                    (circ, input_keys, output)
                })
                .collect();

            if ready_calls.is_empty() {
                break;
            }

            let mut tasks = Vec::with_capacity(ready_calls.len());
            for (circ, input_keys, output) in ready_calls {
                let RCOTSenderOutput {
                    keys: gate_keys, ..
                } = self
                    .ot
                    .try_send_rcot(circ.and_count())
                    .map_err(VmError::execute)?;
                let gate_keys = Key::from_blocks(gate_keys);

                let execute = verifier
                    .execute(circ, &input_keys, &gate_keys)
                    .map_err(VmError::execute)?;
                tasks.push((execute, output));
            }

            let outputs = ctx
                .map(
                    tasks,
                    |ctx, (mut execute, output)| {
                        async move {
                            let mut consumer = execute.consumer();
                            while consumer.wants_adjust() {
                                let adjust: BitVec<u32> = ctx.io_mut().expect_next().await?;
                                for bit in adjust {
                                    consumer.next(bit);
                                }
                            }

                            let output_keys = execute.finish().map_err(VmError::execute)?;

                            Ok((output, output_keys))
                        }
                        .scope_boxed()
                    },
                    |(execute, _)| execute.and_count(),
                )
                .await
                .map_err(VmError::execute)?
                .into_iter()
                .collect::<Result<Vec<_>>>()?;

            for (output, output_keys) in outputs {
                self.store
                    .set_output_keys(output, &output_keys)
                    .map_err(VmError::memory)?;
            }
        }

        if verifier.wants_check() {
            let RCOTSenderOutput {
                keys: svole_keys, ..
            } = self.ot.try_send_rcot(128).map_err(VmError::execute)?;

            let uv = ctx.io_mut().expect_next().await?;
            verifier.check(&svole_keys, uv).map_err(VmError::execute)?;
        }

        Ok(())
    }
}

impl<OT> Callable<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let output = self.store.alloc_output(call.circ().output_len());

        let mut count = call.circ().and_count();

        // If the callstack is empty, we allocate more for the consistency check.
        if self.callstack.is_empty() {
            count += 128
        }

        self.ot.alloc(count).map_err(VmError::execute)?;
        self.callstack.push((call, output));

        Ok(output)
    }
}

impl<OT> Memory<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = VmError;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store.alloc_raw(size).map_err(VmError::memory)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.store.assign_raw(slice, data).map_err(VmError::memory)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.commit_raw(slice).map_err(VmError::memory)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.store.get_raw(slice).map_err(VmError::memory)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store.decode_raw(slice).map_err(VmError::memory)
    }
}

impl<OT> View<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_public_raw(slice).map_err(VmError::view)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_private_raw(slice).map_err(VmError::view)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_blind_raw(slice).map_err(VmError::view)?;
        self.ot.alloc(slice.len()).map_err(VmError::view)?;

        Ok(())
    }
}
