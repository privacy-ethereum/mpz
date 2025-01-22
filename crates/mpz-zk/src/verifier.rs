use async_trait::async_trait;
use mpz_common::{scoped_futures::ScopedFutureExt, Context, ContextError, Flush};
use mpz_core::{bitvec::BitVec, Block};
use mpz_ot::rcot::{RCOTSender, RCOTSenderOutput};
use mpz_vm_core::{
    memory::{
        binary::Binary,
        correlated::{Delta, Key},
        DecodeFuture, Memory, Slice, View,
    },
    Call, Execute, Callable,
};
use mpz_zk_core::{
    store::{VerifierStore, VerifierStoreError},
    Verifier as Core, VerifierError as CoreError,
};
use serio::{stream::IoStreamExt, SinkExt};
use utils::filter_drain::FilterDrain;

type Error = VerifierError;
type Result<T, E = Error> = core::result::Result<T, E>;

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
impl<Ctx, OT> Execute<Ctx> for Verifier<OT>
where
    Ctx: Context,
    OT: RCOTSender<Block> + Flush<Ctx> + Send + 'static,
{
    type Error = Error;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<()> {
        if self.ot.wants_flush() {
            self.ot.flush(ctx).await.map_err(Error::ot)?;
        }

        if self.store.wants_keys() {
            let RCOTSenderOutput { keys, .. } = self
                .ot
                .try_send_rcot(self.store.key_count())
                .map_err(Error::ot)?;
            let keys = Key::from_blocks(keys);

            self.store.set_keys(&keys)?;
        }

        while self.store.wants_flush() {
            let flush = self.store.send_flush()?;
            ctx.io_mut().send(flush).await?;
            let flush = ctx.io_mut().expect_next().await?;
            self.store.receive_flush(flush)?;
        }

        Ok(())
    }

    async fn preprocess(&mut self, _ctx: &mut Ctx) -> Result<()> {
        Ok(())
    }

    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()> {
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
                } = self.ot.try_send_rcot(circ.and_count()).map_err(Error::ot)?;
                let gate_keys = Key::from_blocks(gate_keys);

                let execute = verifier.execute(circ, &input_keys, &gate_keys)?;
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

                            let output_keys = execute.finish()?;

                            Ok((output, output_keys))
                        }
                        .scope_boxed()
                    },
                    |(execute, _)| execute.and_count(),
                )
                .await?
                .into_iter()
                .collect::<Result<Vec<_>, VerifierError>>()?;

            for (output, output_keys) in outputs {
                self.store.set_output_keys(output, &output_keys)?;
            }
        }

        if verifier.wants_check() {
            let RCOTSenderOutput {
                keys: svole_keys, ..
            } = self.ot.try_send_rcot(128).map_err(Error::ot)?;

            let uv = ctx.io_mut().expect_next().await?;
            verifier.check(&svole_keys, uv)?;
        }

        Ok(())
    }
}

impl<OT> Callable<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = Error;

    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let output = self.store.alloc_output(call.circ().output_len());

        let mut count = call.circ().and_count();

        // If the callstack is empty, we allocate more for the consistency check.
        if self.callstack.is_empty() {
            count += 128
        }

        self.ot.alloc(count).map_err(Error::ot)?;
        self.callstack.push((call, output));

        Ok(output)
    }
}

impl<OT> Memory<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store.alloc_raw(size).map_err(Error::from)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.store.assign_raw(slice, data).map_err(Error::from)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.commit_raw(slice).map_err(Error::from)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.store.get_raw(slice).map_err(Error::from)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store.decode_raw(slice).map_err(Error::from)
    }
}

impl<OT> View<Binary> for Verifier<OT>
where
    OT: RCOTSender<Block>,
{
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_blind_raw(slice)?;
        self.ot.alloc(slice.len()).map_err(Error::ot)?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct VerifierError(#[from] ErrorRepr);

impl VerifierError {
    fn ot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ot(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Store(#[from] VerifierStoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error("oblivious transfer error: {0}")]
    Ot(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<CoreError> for VerifierError {
    fn from(err: CoreError) -> Self {
        Self(ErrorRepr::Core(err))
    }
}

impl From<VerifierStoreError> for VerifierError {
    fn from(err: VerifierStoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<std::io::Error> for VerifierError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}

impl From<ContextError> for VerifierError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}
