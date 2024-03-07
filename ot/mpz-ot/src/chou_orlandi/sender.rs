use crate::{chou_orlandi::SenderError, OTError, OTSender, OTSetup, VerifiableOTSender};

use async_trait::async_trait;
use mpz_cointoss as cointoss;
use mpz_common::Context;
use mpz_core::Block;
use mpz_ot_core::chou_orlandi::{sender_state as state, Sender as SenderCore, SenderConfig};
use rand::{thread_rng, Rng};
use serio::{stream::IoStreamExt, SinkExt as _};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use enum_try_as_inner::EnumTryAsInner;

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
pub(crate) enum State {
    Initialized(SenderCore<state::Initialized>),
    Setup(SenderCore<state::Setup>),
    Complete,
    Error,
}

/// Chou-Orlandi sender.
#[derive(Debug)]
pub struct Sender {
    state: State,
    /// The coin toss receiver after revealing one's own seed but before receiving a decommitment
    /// from the coin toss sender.
    cointoss_receiver: Option<cointoss::Receiver<cointoss::receiver_state::Received>>,
}

impl Default for Sender {
    fn default() -> Self {
        Self {
            state: State::Initialized(SenderCore::new(SenderConfig::default())),
            cointoss_receiver: None,
        }
    }
}

impl Sender {
    /// Creates a new Sender
    ///
    /// # Arguments
    ///
    /// * `config` - The sender's configuration
    pub fn new(config: SenderConfig) -> Self {
        Self {
            state: State::Initialized(SenderCore::new(config)),
            cointoss_receiver: None,
        }
    }

    /// Creates a new Sender with the provided RNG seed
    ///
    /// # Arguments
    ///
    /// * `config` - The sender's configuration
    /// * `seed` - The RNG seed used to generate the sender's keys
    pub fn new_with_seed(config: SenderConfig, seed: [u8; 32]) -> Self {
        Self {
            state: State::Initialized(SenderCore::new_with_seed(config, seed)),
            cointoss_receiver: None,
        }
    }
}

#[async_trait]
impl<Ctx: Context> OTSetup<Ctx> for Sender {
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        if self.state.is_setup() {
            return Ok(());
        }

        let sender = std::mem::replace(&mut self.state, State::Error)
            .try_into_initialized()
            .map_err(SenderError::from)?;

        // If the receiver is committed, we run the cointoss protocol
        if sender.config().receiver_commit() {
            let cointoss_seed = thread_rng().gen();
            self.cointoss_receiver = Some(
                cointoss::Receiver::new(vec![cointoss_seed])
                    .receive(ctx)
                    .await
                    .map_err(SenderError::from)?,
            );
        }

        let (msg, sender) = sender.setup();

        ctx.io_mut().send(msg).await?;

        self.state = State::Setup(sender);

        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> OTSender<Ctx, [Block; 2]> for Sender {
    async fn send(&mut self, ctx: &mut Ctx, input: &[[Block; 2]]) -> Result<(), OTError> {
        let mut sender = std::mem::replace(&mut self.state, State::Error)
            .try_into_setup()
            .map_err(SenderError::from)?;

        let receiver_payload = ctx.io_mut().expect_next().await?;

        let input = input.to_vec();
        let (sender, payload) = Backend::spawn(move || {
            sender
                .send(&input, receiver_payload)
                .map(|payload| (sender, payload))
        })
        .await
        .map_err(SenderError::from)?;

        ctx.io_mut().send(payload).await?;

        self.state = State::Setup(sender);

        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> VerifiableOTSender<Ctx, bool, [Block; 2]> for Sender {
    async fn verify_choices(&mut self, ctx: &mut Ctx) -> Result<Vec<bool>, OTError> {
        let sender = std::mem::replace(&mut self.state, State::Error)
            .try_into_setup()
            .map_err(SenderError::from)?;

        let Some(cointoss_receiver) = self.cointoss_receiver.take() else {
            Err(SenderError::InvalidConfig(
                "receiver commitment not enabled".to_string(),
            ))?
        };

        let seed = cointoss_receiver
            .finalize(ctx)
            .await
            .map_err(SenderError::from)?;

        let seed = seed[0].to_bytes();
        // Stretch seed to 32 bytes
        let mut stretched_seed = [0u8; 32];
        stretched_seed[..16].copy_from_slice(&seed);
        stretched_seed[16..].copy_from_slice(&seed);

        let receiver_reveal = ctx.io_mut().expect_next().await?;
        let verified_choices =
            Backend::spawn(move || sender.verify_choices(stretched_seed, receiver_reveal))
                .await
                .map_err(SenderError::from)?;

        self.state = State::Complete;

        Ok(verified_choices)
    }
}
