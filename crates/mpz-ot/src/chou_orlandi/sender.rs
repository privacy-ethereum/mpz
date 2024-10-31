use async_trait::async_trait;
use mpz_common::{future::MaybeDone, Context, Flush};
use mpz_core::Block;
use mpz_ot_core::{
    chou_orlandi::{sender_state as state, Sender as Core, SenderError as CoreError},
    ot::{OTSender, OTSenderOutput},
};
use serio::{stream::IoStreamExt, SinkExt};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

type Error = SenderError;

/// Chou-Orlandi sender.
#[derive(Debug)]
pub struct Sender {
    state: State,
}

#[derive(Debug)]
enum State {
    Initialized(Core<state::Initialized>),
    Setup(Core<state::Setup>),
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Error)
    }
}

impl Sender {
    /// Creates a new Sender
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new Sender with the provided RNG seed
    ///
    /// # Arguments
    ///
    /// * `seed` - The RNG seed used to generate the sender's keys
    pub fn new_with_seed(seed: [u8; 32]) -> Self {
        Self {
            state: State::Initialized(Core::new_with_seed(seed)),
        }
    }
}

impl Default for Sender {
    fn default() -> Self {
        Self {
            state: State::Initialized(Core::new()),
        }
    }
}

impl OTSender<Block> for Sender {
    type Error = Error;
    type Future = MaybeDone<OTSenderOutput>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        match &mut self.state {
            State::Initialized(sender) => sender.alloc(count).map_err(Error::from),
            State::Setup(sender) => sender.alloc(count).map_err(Error::from),
            State::Error => Err(Error::state("can not allocate, sender is in error state")),
        }
    }

    fn queue_send_ot(&mut self, msgs: &[[Block; 2]]) -> Result<Self::Future, Self::Error> {
        match &mut self.state {
            State::Initialized(sender) => sender.queue_send_ot(msgs).map_err(Error::from),
            State::Setup(sender) => sender.queue_send_ot(msgs).map_err(Error::from),
            State::Error => Err(Error::state("can not queue ot, sender is in error state")),
        }
    }
}

#[async_trait]
impl<Ctx> Flush<Ctx> for Sender
where
    Ctx: Context,
{
    type Error = Error;

    fn wants_flush(&self) -> bool {
        match &self.state {
            State::Initialized(_) => true,
            State::Setup(sender) => sender.wants_recv(),
            State::Error => false,
        }
    }

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), Self::Error> {
        let mut sender = match self.state.take() {
            State::Initialized(sender) => {
                let (setup, sender) = sender.setup();
                ctx.io_mut().send(setup).await?;
                sender
            }
            State::Setup(sender) => sender,
            State::Error => return Err(Error::state("can not flush, sender is in error state")),
        };

        if !sender.wants_recv() {
            self.state = State::Setup(sender);
            return Ok(());
        }

        let payload = ctx.io_mut().expect_next().await?;

        let (payload, sender) =
            Backend::spawn(|| sender.send(payload).map(|payload| (payload, sender))).await?;

        ctx.io_mut().send(payload).await?;

        self.state = State::Setup(sender);

        Ok(())
    }
}

/// Error for [`Sender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SenderError(#[from] ErrorRepr);

impl SenderError {
    fn state(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::State(msg.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("state error: {0}")]
    State(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for SenderError {
    fn from(err: CoreError) -> Self {
        SenderError(ErrorRepr::Core(err))
    }
}

impl From<std::io::Error> for SenderError {
    fn from(err: std::io::Error) -> Self {
        SenderError(ErrorRepr::Io(err))
    }
}
