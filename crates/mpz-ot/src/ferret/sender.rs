use std::mem;

use crate::{ferret::mpcot, Correlation, RandomCOTSender};
use async_trait::async_trait;
use mpz_common::{cpu::CpuBackend, Allocate, Context, Preprocess};
use mpz_core::Block;
use mpz_ot_core::{
    ferret::sender::{state, Sender as SenderCore},
    RCOTSenderOutput,
};
use serio::stream::IoStreamExt;

use super::{FerretConfig, SenderError};
use crate::OTError;

#[derive(Debug)]
pub(crate) enum State {
    Initialized(SenderCore<state::Initialized>),
    Extension(SenderCore<state::Extension>),
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

/// Ferret Sender.
#[derive(Debug)]
pub struct Sender<RandomCOT> {
    state: State,
    config: FerretConfig,
    rcot: RandomCOT,
    alloc: usize,
}

impl<RandomCOT> Sender<RandomCOT> {
    /// Creates a new Sender.
    pub fn new(config: FerretConfig, rcot: RandomCOT) -> Self {
        Self {
            state: State::Initialized(SenderCore::new()),
            config,
            rcot,
            alloc: 0,
        }
    }

    /// Setup with provided delta.
    ///
    /// # Argument
    ///
    /// * `ctx` - The channel context.
    pub async fn setup<Ctx>(&mut self, ctx: &mut Ctx) -> Result<(), SenderError>
    where
        Ctx: Context,
        RandomCOT: RandomCOTSender<Ctx, Block> + Correlation<Correlation = Block>,
    {
        let State::Initialized(sender) = self.state.take() else {
            return Err(SenderError::state("sender not in initialized state"));
        };

        let params = self.config.lpn_parameters();
        let lpn_type = self.config.lpn_type();

        // Get random blocks from ideal Random COT.
        let RCOTSenderOutput { msgs: v, .. } =
            self.rcot.send_random_correlated(ctx, params.k).await?;

        // Get seed for LPN matrix from receiver.
        let seed = ctx.io_mut().expect_next().await?;

        // Ferret core setup.
        let sender = sender.setup(self.rcot.delta(), params, lpn_type, seed, &v)?;

        self.state = State::Extension(sender);

        Ok(())
    }

    /// Performs extension.
    ///
    /// # Argument
    ///
    /// * `ctx` - Thread context.
    /// * `count` - The number of OTs to extend.
    pub async fn extend<Ctx: Context>(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<(), SenderError>
    where
        RandomCOT: RandomCOTSender<Ctx, Block> + Send,
    {
        let State::Extension(mut sender) = self.state.take() else {
            return Err(SenderError::state("sender not in extension state"));
        };

        let lpn_type = self.config.lpn_type();
        let delta = sender.delta();
        let target = sender.remaining() + count;
        while sender.remaining() < target {
            let (t, n) = sender.get_mpcot_query();

            let s = if sender.remaining() < self.config.bootstrap_rate() {
                mpcot::send(ctx, &mut self.rcot, delta, lpn_type, t, n).await?
            } else {
                mpcot::send(
                    ctx,
                    &mut BootstrappedSender(&mut sender),
                    delta,
                    lpn_type,
                    t,
                    n,
                )
                .await?
            };

            sender = CpuBackend::blocking(move || sender.extend(s).map(|()| sender)).await?;
        }

        self.state = State::Extension(sender);

        Ok(())
    }
}

impl<RandomCOT> Correlation for Sender<RandomCOT>
where
    RandomCOT: Correlation<Correlation = Block>,
{
    type Correlation = Block;

    fn delta(&self) -> Self::Correlation {
        self.rcot.delta()
    }
}

#[async_trait]
impl<Ctx, RandomCOT> RandomCOTSender<Ctx, Block> for Sender<RandomCOT>
where
    RandomCOT: Correlation<Correlation = Block> + Send,
{
    async fn send_random_correlated(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTSenderOutput<Block>, OTError> {
        let State::Extension(sender) = &mut self.state else {
            return Err(SenderError::state("sender not in extension state").into());
        };

        sender
            .consume(count)
            .map_err(SenderError::from)
            .map_err(OTError::from)
    }
}

impl<RandomCOT> Allocate for Sender<RandomCOT> {
    fn alloc(&mut self, count: usize) {
        self.alloc += count;
    }
}

#[async_trait]
impl<Ctx, RandomCOT> Preprocess<Ctx> for Sender<RandomCOT>
where
    Ctx: Context,
    RandomCOT: RandomCOTSender<Ctx, Block> + Send,
{
    type Error = SenderError;

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        let count = mem::take(&mut self.alloc);
        self.extend(ctx, count).await
    }
}

#[derive(Debug)]
struct BootstrappedSender<'a>(&'a mut SenderCore<state::Extension>);

impl Correlation for BootstrappedSender<'_> {
    type Correlation = Block;

    fn delta(&self) -> Block {
        self.0.delta()
    }
}

#[async_trait]
impl<Ctx> RandomCOTSender<Ctx, Block> for BootstrappedSender<'_> {
    async fn send_random_correlated(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTSenderOutput<Block>, OTError> {
        self.0
            .consume(count)
            .map_err(SenderError::from)
            .map_err(OTError::from)
    }
}
