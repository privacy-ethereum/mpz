use std::mem;

use async_trait::async_trait;
use mpz_common::{cpu::CpuBackend, Allocate, Context, Preprocess};
use mpz_core::{prg::Prg, Block};
use mpz_ot_core::{
    ferret::receiver::{state, Receiver as ReceiverCore},
    RCOTReceiverOutput,
};
use serio::SinkExt;

use crate::{
    ferret::{mpcot, FerretConfig, ReceiverError},
    OTError, RandomCOTReceiver,
};

#[derive(Debug)]
pub(crate) enum State {
    Initialized(ReceiverCore<state::Initialized>),
    Extension(ReceiverCore<state::Extension>),
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

/// Ferret Receiver.
#[derive(Debug)]
pub struct Receiver<RandomCOT> {
    state: State,
    config: FerretConfig,
    rcot: RandomCOT,
    alloc: usize,
}

impl<RandomCOT> Receiver<RandomCOT> {
    /// Creates a new Receiver.
    ///
    /// # Arguments.
    ///
    /// * `config` - Ferret configuration.
    pub fn new(config: FerretConfig, rcot: RandomCOT) -> Self {
        Self {
            state: State::Initialized(ReceiverCore::new()),
            config,
            rcot,
            alloc: 0,
        }
    }

    /// Setup for receiver.
    ///
    /// # Arguments.
    ///
    /// * `ctx` - The channel context.
    pub async fn setup<Ctx>(&mut self, ctx: &mut Ctx) -> Result<(), ReceiverError>
    where
        Ctx: Context,
        RandomCOT: RandomCOTReceiver<Ctx, bool, Block>,
    {
        let State::Initialized(receiver) = self.state.take() else {
            return Err(ReceiverError::state("receiver not in initialized state"));
        };

        let params = self.config.lpn_parameters();
        let lpn_type = self.config.lpn_type();

        // Get random blocks from ideal Random COT.

        let RCOTReceiverOutput {
            choices: u,
            msgs: w,
            ..
        } = self.rcot.receive_random_correlated(ctx, params.k).await?;

        let seed = Prg::new().random_block();

        let (receiver, seed) = receiver.setup(params, lpn_type, seed, &u, &w)?;

        ctx.io_mut().send(seed).await?;

        self.state = State::Extension(receiver);

        Ok(())
    }

    /// Performs extension.
    ///
    /// # Arguments
    ///
    /// * `ctx` - Thread context.
    /// * `count` - The number of OTs to extend.
    pub async fn extend<Ctx>(&mut self, ctx: &mut Ctx, count: usize) -> Result<(), ReceiverError>
    where
        Ctx: Context,
        RandomCOT: RandomCOTReceiver<Ctx, bool, Block> + Send,
    {
        let State::Extension(mut receiver) = self.state.take() else {
            return Err(ReceiverError::state("receiver not in extension state"));
        };

        let lpn_type = self.config.lpn_type();
        let target = receiver.remaining() + count;
        while receiver.remaining() < target {
            let (alphas, n) = receiver.get_mpcot_query();

            let r = if receiver.remaining() < self.config.bootstrap_rate() {
                mpcot::receive(ctx, &mut self.rcot, lpn_type, alphas, n as u32).await?
            } else {
                mpcot::receive(
                    ctx,
                    &mut BootstrappedReceiver(&mut receiver),
                    lpn_type,
                    alphas,
                    n as u32,
                )
                .await?
            };

            receiver = CpuBackend::blocking(move || receiver.extend(r).map(|()| receiver)).await?;
        }

        self.state = State::Extension(receiver);

        Ok(())
    }
}

#[async_trait]
impl<Ctx, RandomCOT> RandomCOTReceiver<Ctx, bool, Block> for Receiver<RandomCOT>
where
    RandomCOT: Send,
{
    async fn receive_random_correlated(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, OTError> {
        let State::Extension(receiver) = &mut self.state else {
            return Err(ReceiverError::state("receiver not in extension state").into());
        };

        receiver
            .consume(count)
            .map_err(ReceiverError::from)
            .map_err(OTError::from)
    }
}

impl<RandomCOT> Allocate for Receiver<RandomCOT> {
    fn alloc(&mut self, count: usize) {
        self.alloc += count;
    }
}

#[async_trait]
impl<Ctx, RandomCOT> Preprocess<Ctx> for Receiver<RandomCOT>
where
    Ctx: Context,
    RandomCOT: RandomCOTReceiver<Ctx, bool, Block> + Send,
{
    type Error = ReceiverError;

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        let count = mem::take(&mut self.alloc);
        self.extend(ctx, count).await
    }
}

#[derive(Debug)]
struct BootstrappedReceiver<'a>(&'a mut ReceiverCore<state::Extension>);

#[async_trait]
impl<Ctx> RandomCOTReceiver<Ctx, bool, Block> for BootstrappedReceiver<'_> {
    async fn receive_random_correlated(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, OTError> {
        self.0
            .consume(count)
            .map_err(ReceiverError::from)
            .map_err(OTError::from)
    }
}
