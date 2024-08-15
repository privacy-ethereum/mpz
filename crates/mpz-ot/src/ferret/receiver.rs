use std::mem;

use async_trait::async_trait;
use mpz_common::{cpu::CpuBackend, Allocate, Context, Preprocess};
use mpz_core::{prg::Prg, Block};
use mpz_ot_core::{
    ferret::{
        receiver::{state, Receiver as ReceiverCore},
        LpnType, CSP, CUCKOO_HASH_NUM,
    },
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
    buffer: ReceiverBuffer,
    buffer_len: usize,
}

impl<RandomCOT> Receiver<RandomCOT> {
    /// Creates a new Receiver.
    ///
    /// # Arguments.
    ///
    /// * `config` - The Ferret config.
    /// * `rcot` - The random COT in setup.
    pub fn new(config: FerretConfig, rcot: RandomCOT) -> Self {
        Self {
            state: State::Initialized(ReceiverCore::new()),
            config,
            rcot,
            alloc: 0,
            buffer: Default::default(),
            buffer_len: 0,
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

        // Compute the number of buffered OTs.
        self.buffer_len = match lpn_type {
            // The number here is a rough estimation to ensure sufficient buffer.
            // It is hard to precisely compute the number because of the Cuckoo hashes.
            LpnType::Uniform => {
                let m = (1.5 * (params.t as f32)).ceil() as usize;
                m * ((2 * CUCKOO_HASH_NUM * params.n / m)
                    .checked_next_power_of_two()
                    .expect("The length should be less than usize::MAX / 2 - 1")
                    .ilog2() as usize)
                    + CSP
            }
            // In our chosen paramters, we always set n is divided by t and n/t is a power of 2.
            LpnType::Regular => {
                assert!(params.n % params.t == 0 && (params.n / params.t).is_power_of_two());
                params.t * ((params.n / params.t).ilog2() as usize) + CSP
            }
        };

        // Get random blocks from ideal Random COT.
        let RCOTReceiverOutput {
            choices: mut u,
            msgs: mut w,
            id,
        } = self
            .rcot
            .receive_random_correlated(ctx, params.k + self.buffer_len)
            .await?;

        // Initiate buffer.
        let buffer = RCOTReceiverOutput {
            id,
            choices: u.drain(0..self.buffer_len).collect(),
            msgs: w.drain(0..self.buffer_len).collect(),
        };
        self.buffer = ReceiverBuffer::new(buffer);

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

            let r = mpcot::receive(ctx, &mut self.buffer, lpn_type, alphas, n as u32).await?;

            receiver = CpuBackend::blocking(move || receiver.extend(r).map(|()| receiver)).await?;

            // Update receiver buffer.
            let buffer = receiver
                .consume(self.buffer_len)
                .map_err(ReceiverError::from)
                .map_err(OTError::from)?;

            self.buffer = ReceiverBuffer::new(buffer);
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
struct ReceiverBuffer {
    buffer: RCOTReceiverOutput<bool, Block>,
}

impl ReceiverBuffer {
    fn new(buffer: RCOTReceiverOutput<bool, Block>) -> Self {
        Self { buffer }
    }
}

impl Default for ReceiverBuffer {
    fn default() -> Self {
        ReceiverBuffer {
            buffer: RCOTReceiverOutput {
                id: Default::default(),
                choices: Vec::new(),
                msgs: Vec::new(),
            },
        }
    }
}

#[async_trait]
impl<Ctx> RandomCOTReceiver<Ctx, bool, Block> for ReceiverBuffer {
    async fn receive_random_correlated(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, OTError> {
        if count > self.buffer.choices.len() {
            return Err(ReceiverError::io(format!(
                "insufficient OTs: {} < {count}",
                self.buffer.choices.len()
            ))
            .into());
        }

        let choices = self.buffer.choices.drain(0..count).collect();
        let msgs = self.buffer.msgs.drain(0..count).collect();
        Ok(RCOTReceiverOutput {
            id: self.buffer.id.next(),
            choices,
            msgs,
        })
    }
}
