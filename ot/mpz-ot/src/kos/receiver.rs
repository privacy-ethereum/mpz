use async_trait::async_trait;
use itybity::{FromBitIterator, IntoBitIterator};
use mpz_cointoss as cointoss;
use mpz_common::{scoped_futures::ScopedFutureExt, Context};
use mpz_core::{prg::Prg, Block};
use mpz_ot_core::kos::{
    msgs::StartExtend, pad_ot_count, receiver_state as state, Receiver as ReceiverCore,
    ReceiverConfig, ReceiverKeys, CSP,
};

use enum_try_as_inner::EnumTryAsInner;
use rand::{thread_rng, Rng};
use rand_core::{RngCore, SeedableRng};
use serio::{stream::IoStreamExt as _, SinkExt as _};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use super::{ReceiverError, ReceiverVerifyError, EXTEND_CHUNK_SIZE};
use crate::{
    OTError, OTReceiver, OTSender, OTSetup, RandomOTReceiver, VerifiableOTReceiver,
    VerifiableOTSender,
};

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
pub(crate) enum State {
    Initialized(Box<ReceiverCore<state::Initialized>>),
    Extension(Box<ReceiverCore<state::Extension>>),
    Verify(ReceiverCore<state::Verify>),
    Error,
}

/// KOS receiver.
#[derive(Debug)]
pub struct Receiver<BaseOT> {
    state: State,
    base: BaseOT,

    cointoss_receiver: Option<cointoss::Receiver<cointoss::receiver_state::Received>>,
}

impl<BaseOT> Receiver<BaseOT>
where
    BaseOT: Send,
{
    /// Creates a new receiver.
    ///
    /// # Arguments
    ///
    /// * `config` - The receiver's configuration
    pub fn new(config: ReceiverConfig, base: BaseOT) -> Self {
        Self {
            state: State::Initialized(Box::new(ReceiverCore::new(config))),
            base,
            cointoss_receiver: None,
        }
    }

    /// The number of remaining OTs which can be consumed.
    pub fn remaining(&self) -> Result<usize, ReceiverError> {
        Ok(self.state.try_as_extension()?.remaining())
    }

    /// Returns the provided number of keys.
    pub(crate) fn take_keys(&mut self, count: usize) -> Result<ReceiverKeys, ReceiverError> {
        self.state
            .try_as_extension_mut()?
            .keys(count)
            .map_err(ReceiverError::from)
    }

    /// Performs OT extension.
    ///
    /// # Arguments
    ///
    /// * `sink` - The sink to send messages to the sender
    /// * `stream` - The stream to receive messages from the sender
    /// * `count` - The number of OTs to extend
    pub async fn extend<Ctx: Context>(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<(), ReceiverError> {
        let mut ext_receiver =
            std::mem::replace(&mut self.state, State::Error).try_into_extension()?;

        let count = pad_ot_count(count);

        // Extend the OTs.
        let (mut ext_receiver, extend) = Backend::spawn(move || {
            ext_receiver
                .extend(count)
                .map(|extend| (ext_receiver, extend))
        })
        .await?;

        // Send the extend message and cointoss commitment.
        ctx.io_mut().feed(StartExtend { count }).await?;
        for extend in extend.into_chunks(EXTEND_CHUNK_SIZE) {
            ctx.io_mut().feed(extend).await?;
        }
        ctx.io_mut().flush().await?;

        // Sample chi_seed with coin-toss.
        let seed = thread_rng().gen();
        let chi_seed = cointoss::cointoss_sender(ctx, vec![seed]).await?[0];

        // Compute consistency check.
        let (ext_receiver, check) = Backend::spawn(move || {
            ext_receiver
                .check(chi_seed)
                .map(|check| (ext_receiver, check))
        })
        .await?;

        // Send correlation check value.
        ctx.io_mut().send(check).await?;

        self.state = State::Extension(ext_receiver);

        Ok(())
    }
}

impl<BaseOT> Receiver<BaseOT>
where
    BaseOT: Send,
{
    pub(crate) async fn verify_delta<Ctx: Context>(
        &mut self,
        ctx: &mut Ctx,
    ) -> Result<(), ReceiverError>
    where
        BaseOT: VerifiableOTSender<Ctx, bool, [Block; 2]>,
    {
        let receiver = std::mem::replace(&mut self.state, State::Error).try_into_extension()?;

        // Finalize coin toss to determine expected delta
        let Some(cointoss_receiver) = self.cointoss_receiver.take() else {
            return Err(ReceiverError::ConfigError(
                "committed sender not configured".to_string(),
            ))?;
        };

        let expected_delta = cointoss_receiver
            .finalize(ctx)
            .await
            .map_err(ReceiverError::from)?[0];

        // Receive delta by verifying the sender's base OT choices.
        let choices = self.base.verify_choices(ctx).await?;

        let actual_delta = <[u8; 16]>::from_lsb0_iter(choices).into();

        if expected_delta != actual_delta {
            return Err(ReceiverError::from(ReceiverVerifyError::InconsistentDelta));
        }

        self.state = State::Verify(receiver.start_verification(actual_delta)?);

        Ok(())
    }
}

#[async_trait]
impl<Ctx, BaseOT> OTSetup<Ctx> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: OTSetup<Ctx> + OTSender<Ctx, [Block; 2]> + Send,
{
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        if self.state.is_extension() {
            return Ok(());
        }

        let ext_receiver = std::mem::replace(&mut self.state, State::Error)
            .try_into_initialized()
            .map_err(ReceiverError::from)?;

        // If the sender is committed, we run a coin toss
        if ext_receiver.config().sender_commit() {
            let cointoss_seed = thread_rng().gen();
            let base = &mut self.base;

            let (cointoss_receiver, _) = ctx
                .try_join(
                    |ctx| {
                        async move {
                            cointoss::Receiver::new(vec![cointoss_seed])
                                .receive(ctx)
                                .await
                                .map_err(ReceiverError::from)
                        }
                        .scope_boxed()
                    },
                    |ctx| {
                        async move { base.setup(ctx).await.map_err(ReceiverError::from) }
                            .scope_boxed()
                    },
                )
                .await?;

            self.cointoss_receiver = Some(cointoss_receiver);
        } else {
            self.base.setup(ctx).await?;
        }

        let seeds: [[Block; 2]; CSP] = std::array::from_fn(|_| thread_rng().gen());

        // Send seeds to sender
        self.base.send(ctx, &seeds).await?;

        let ext_receiver = ext_receiver.setup(seeds);

        self.state = State::Extension(Box::new(ext_receiver));

        Ok(())
    }
}

#[async_trait]
impl<Ctx, BaseOT> OTReceiver<Ctx, bool, Block> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: Send,
{
    async fn receive(&mut self, ctx: &mut Ctx, choices: &[bool]) -> Result<Vec<Block>, OTError> {
        let receiver = self
            .state
            .try_as_extension_mut()
            .map_err(ReceiverError::from)?;

        let mut receiver_keys = receiver.keys(choices.len()).map_err(ReceiverError::from)?;

        let choices = choices.into_lsb0_vec();
        let derandomize = receiver_keys
            .derandomize(&choices)
            .map_err(ReceiverError::from)?;

        // Send derandomize message
        ctx.io_mut().send(derandomize).await?;

        // Receive payload
        let payload = ctx.io_mut().expect_next().await?;

        let received = Backend::spawn(move || {
            receiver_keys
                .decrypt_blocks(payload)
                .map_err(ReceiverError::from)
        })
        .await?;

        Ok(received)
    }
}

#[async_trait]
impl<Ctx, BaseOT> RandomOTReceiver<Ctx, bool, Block> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: Send,
{
    async fn receive_random(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<(Vec<bool>, Vec<Block>), OTError> {
        let receiver = self
            .state
            .try_as_extension_mut()
            .map_err(ReceiverError::from)?;

        let (choices, random_outputs) = receiver
            .keys(count)
            .map_err(ReceiverError::from)?
            .take_choices_and_keys();

        Ok((choices, random_outputs))
    }
}

#[async_trait]
impl<Ctx, const N: usize, BaseOT> OTReceiver<Ctx, bool, [u8; N]> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: Send,
{
    async fn receive(&mut self, ctx: &mut Ctx, choices: &[bool]) -> Result<Vec<[u8; N]>, OTError> {
        let receiver = self
            .state
            .try_as_extension_mut()
            .map_err(ReceiverError::from)?;

        let mut receiver_keys = receiver.keys(choices.len()).map_err(ReceiverError::from)?;

        let choices = choices.into_lsb0_vec();
        let derandomize = receiver_keys
            .derandomize(&choices)
            .map_err(ReceiverError::from)?;

        // Send derandomize message
        ctx.io_mut().send(derandomize).await?;

        // Receive payload
        let payload = ctx.io_mut().expect_next().await?;

        let received = Backend::spawn(move || {
            receiver_keys
                .decrypt_bytes(payload)
                .map_err(ReceiverError::from)
        })
        .await?;

        Ok(received)
    }
}

#[async_trait]
impl<Ctx, const N: usize, BaseOT> RandomOTReceiver<Ctx, bool, [u8; N]> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: Send,
{
    async fn receive_random(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<(Vec<bool>, Vec<[u8; N]>), OTError> {
        let receiver = self
            .state
            .try_as_extension_mut()
            .map_err(ReceiverError::from)?;

        let (choices, random_outputs) = receiver
            .keys(count)
            .map_err(ReceiverError::from)?
            .take_choices_and_keys();

        Ok((
            choices,
            random_outputs
                .into_iter()
                .map(|block| {
                    let mut prg = Prg::from_seed(block);
                    let mut out = [0_u8; N];
                    prg.fill_bytes(&mut out);
                    out
                })
                .collect(),
        ))
    }
}

#[async_trait]
impl<Ctx, BaseOT> VerifiableOTReceiver<Ctx, bool, Block, [Block; 2]> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: VerifiableOTSender<Ctx, bool, [Block; 2]> + Send,
{
    async fn verify(
        &mut self,
        ctx: &mut Ctx,
        id: usize,
        msgs: &[[Block; 2]],
    ) -> Result<(), OTError> {
        // Verify delta if we haven't yet.
        if self.state.is_extension() {
            self.verify_delta(ctx).await?;
        }

        let receiver = self.state.try_as_verify().map_err(ReceiverError::from)?;

        let record = receiver
            .remove_record(id as u32)
            .map_err(ReceiverError::from)?;

        let msgs = msgs.to_vec();
        Backend::spawn(move || record.verify(&msgs))
            .await
            .map_err(ReceiverError::from)?;

        Ok(())
    }
}
