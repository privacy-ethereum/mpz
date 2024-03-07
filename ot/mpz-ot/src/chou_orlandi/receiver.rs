use async_trait::async_trait;

use itybity::BitIterable;
use mpz_cointoss as cointoss;
use mpz_common::Context;
use mpz_core::Block;
use mpz_ot_core::chou_orlandi::{
    receiver_state as state, Receiver as ReceiverCore, ReceiverConfig,
};

use enum_try_as_inner::EnumTryAsInner;
use rand::{thread_rng, Rng};
use serio::{stream::IoStreamExt as _, SinkExt as _};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use crate::{CommittedOTReceiver, OTError, OTReceiver, OTSetup};

use super::ReceiverError;

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
pub(crate) enum State {
    Initialized {
        config: ReceiverConfig,
        seed: Option<[u8; 32]>,
    },
    Setup(Box<ReceiverCore<state::Setup>>),
    Complete,
    Error,
}

/// Chou-Orlandi receiver.
#[derive(Debug)]
pub struct Receiver {
    state: State,
    cointoss_sender: Option<cointoss::Sender<cointoss::sender_state::Received>>,
}

impl Default for Receiver {
    fn default() -> Self {
        Self {
            state: State::Initialized {
                config: ReceiverConfig::default(),
                seed: None,
            },
            cointoss_sender: None,
        }
    }
}

impl Receiver {
    /// Creates a new receiver.
    ///
    /// # Arguments
    ///
    /// * `config` - The receiver's configuration
    pub fn new(config: ReceiverConfig) -> Self {
        Self {
            state: State::Initialized { config, seed: None },
            cointoss_sender: None,
        }
    }

    /// Creates a new receiver with the provided RNG seed.
    ///
    /// # Arguments
    ///
    /// * `config` - The receiver's configuration
    /// * `seed` - The RNG seed used to generate the receiver's keys.
    pub fn new_with_seed(config: ReceiverConfig, seed: [u8; 32]) -> Self {
        Self {
            state: State::Initialized {
                config,
                seed: Some(seed),
            },
            cointoss_sender: None,
        }
    }
}

#[async_trait]
impl<Ctx: Context> OTSetup<Ctx> for Receiver {
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        if self.state.is_setup() {
            return Ok(());
        }

        let (config, seed) = std::mem::replace(&mut self.state, State::Error)
            .try_into_initialized()
            .map_err(ReceiverError::from)?;

        // If the receiver is committed, we generate the seed using a cointoss.
        let seed = if config.receiver_commit() {
            if seed.is_some() {
                return Err(ReceiverError::InvalidConfig(
                    "committed receiver seed must be generated using coin toss".to_string(),
                ))?;
            }

            let cointoss_seed = thread_rng().gen();
            let (seeds, cointoss_sender) = cointoss::Sender::new(vec![cointoss_seed])
                .commit(ctx)
                .await
                .map_err(ReceiverError::from)?
                .receive(ctx)
                .await
                .map_err(ReceiverError::from)?;

            self.cointoss_sender = Some(cointoss_sender);

            let seed = seeds[0].to_bytes();
            // Stretch seed to 32 bytes
            let mut stretched_seed = [0u8; 32];
            stretched_seed[..16].copy_from_slice(&seed);
            stretched_seed[16..].copy_from_slice(&seed);

            stretched_seed
        } else {
            seed.unwrap_or_else(|| thread_rng().gen())
        };

        let sender_setup = ctx.io_mut().expect_next().await?;
        let receiver =
            Backend::spawn(move || ReceiverCore::new_with_seed(config, seed).setup(sender_setup))
                .await;

        self.state = State::Setup(Box::new(receiver));

        Ok(())
    }
}

#[async_trait]
impl<Ctx, T> OTReceiver<Ctx, T, Block> for Receiver
where
    Ctx: Context,
    T: BitIterable + Send + Sync + Clone + 'static,
{
    async fn receive(&mut self, ctx: &mut Ctx, choices: &[T]) -> Result<Vec<Block>, OTError> {
        let mut receiver = std::mem::replace(&mut self.state, State::Error)
            .try_into_setup()
            .map_err(ReceiverError::from)?;

        let choices = choices.to_vec();
        let (mut receiver, receiver_payload) = Backend::spawn(move || {
            let payload = receiver.receive_random(&choices);
            (receiver, payload)
        })
        .await;

        ctx.io_mut().send(receiver_payload).await?;

        let sender_payload = ctx.io_mut().expect_next().await?;

        let (receiver, data) = Backend::spawn(move || {
            receiver
                .receive(sender_payload)
                .map(|data| (receiver, data))
        })
        .await
        .map_err(ReceiverError::from)?;

        self.state = State::Setup(receiver);

        Ok(data)
    }
}

#[async_trait]
impl<Ctx: Context> CommittedOTReceiver<Ctx, bool, Block> for Receiver {
    async fn reveal_choices(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        let receiver = std::mem::replace(&mut self.state, State::Error)
            .try_into_setup()
            .map_err(ReceiverError::from)?;

        let Some(cointoss_sender) = self.cointoss_sender.take() else {
            return Err(ReceiverError::InvalidConfig(
                "receiver not configured to commit".to_string(),
            )
            .into());
        };

        cointoss_sender
            .finalize(ctx)
            .await
            .map_err(ReceiverError::from)?;

        let reveal = receiver.reveal_choices().map_err(ReceiverError::from)?;
        ctx.io_mut().send(reveal).await?;

        self.state = State::Complete;

        Ok(())
    }
}
