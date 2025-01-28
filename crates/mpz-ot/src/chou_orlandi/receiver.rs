use async_trait::async_trait;

use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot_core::{
    chou_orlandi::{receiver_state as state, Receiver as Core, ReceiverError as CoreError},
    ot::OTReceiver,
};

use serio::{stream::IoStreamExt as _, SinkExt as _};

type Error = ReceiverError;

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

/// Chou-Orlandi receiver.
#[derive(Debug)]
pub struct Receiver {
    state: State,
}

impl Default for Receiver {
    fn default() -> Self {
        Self {
            state: State::Initialized(Core::new()),
        }
    }
}

impl Receiver {
    /// Creates a new receiver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new receiver with the provided RNG seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - The RNG seed used to generate the receiver's keys.
    pub fn new_with_seed(seed: [u8; 32]) -> Self {
        Self {
            state: State::Initialized(Core::new_with_seed(seed)),
        }
    }
}

impl OTReceiver<bool, Block> for Receiver {
    type Error = Error;
    type Future = <Core as OTReceiver<bool, Block>>::Future;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        match &mut self.state {
            State::Initialized(receiver) => receiver.alloc(count).map_err(Error::from),
            State::Setup(receiver) => receiver.alloc(count).map_err(Error::from),
            State::Error => Err(Error::state("can not allocate, receiver is in error state")),
        }
    }

    fn queue_recv_ot(&mut self, choices: &[bool]) -> Result<Self::Future, Self::Error> {
        match &mut self.state {
            State::Initialized(receiver) => receiver.queue_recv_ot(choices).map_err(Error::from),
            State::Setup(receiver) => receiver.queue_recv_ot(choices).map_err(Error::from),
            State::Error => Err(Error::state("can not queue ot, receiver is in error state")),
        }
    }
}

#[async_trait]
impl Flush for Receiver {
    type Error = Error;

    fn wants_flush(&self) -> bool {
        match &self.state {
            State::Initialized(_) => true,
            State::Setup(receiver) => receiver.wants_flush(),
            State::Error => false,
        }
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<(), Self::Error> {
        let mut receiver = match self.state.take() {
            State::Initialized(receiver) => {
                let payload = ctx.io_mut().expect_next().await?;
                receiver.setup(payload)
            }
            State::Setup(receiver) => receiver,
            State::Error => return Err(Error::state("cannot flush, receiver is in error state")),
        };

        if !receiver.wants_flush() {
            self.state = State::Setup(receiver);
            return Ok(());
        }

        let payload = receiver.choose();

        ctx.io_mut().send(payload).await?;
        let payload = ctx.io_mut().expect_next().await?;

        receiver.receive(payload)?;

        self.state = State::Setup(receiver);

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ReceiverError(#[from] ErrorRepr);

impl ReceiverError {
    fn state(err: impl Into<String>) -> Self {
        Self(ErrorRepr::State(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[source] CoreError),
    #[error("state error: {0}")]
    State(String),
    #[error("io error: {0}")]
    Io(#[source] std::io::Error),
}

impl From<CoreError> for ReceiverError {
    fn from(e: CoreError) -> Self {
        Self(ErrorRepr::Core(e))
    }
}

impl From<std::io::Error> for ReceiverError {
    fn from(e: std::io::Error) -> Self {
        Self(ErrorRepr::Io(e))
    }
}
