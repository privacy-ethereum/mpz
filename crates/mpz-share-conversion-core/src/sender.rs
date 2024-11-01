//! Share conversion sender.

use std::{collections::VecDeque, marker::PhantomData};

use mpz_common::future::{new_output, MaybeDone, Sender as OutputSender};
use mpz_fields::Field;
use mpz_ole_core::{Adjust, ROLESender, ROLESenderOutput};

use crate::{
    a2m::{A2MError, A2MSenderAdjust, A2MSenderDerand},
    A2MOutput, AdditiveToMultiplicative, M2AOutput, MultiplicativeToAdditive, RecvA2M, RecvM2A,
    SendA2M, SendM2A,
};

#[derive(Debug)]
struct QueuedA2M<F> {
    count: usize,
    sender: OutputSender<A2MOutput<F>>,
}

#[derive(Debug)]
struct QueuedM2A<F> {
    count: usize,
    sender: OutputSender<M2AOutput<F>>,
}

/// Sender for share conversion.
#[derive(Debug)]
pub struct Sender<T, F> {
    role: T,
    queue_a2m: VecDeque<QueuedA2M<F>>,
    queue_m2a: VecDeque<QueuedM2A<F>>,
    a2m_inputs: Vec<F>,
    a2m_adjust: Vec<A2MSenderAdjust<F>>,
    m2a_inputs: Vec<F>,
    m2a_adjust: Vec<Adjust<F>>,
    _pd: PhantomData<F>,
}

impl<T, F> Sender<T, F> {
    /// Creates a new sender.
    ///
    /// # Arguments
    ///
    /// * `role` - ROLE sender.
    pub fn new(role: T) -> Self {
        Self {
            role,
            queue_a2m: VecDeque::new(),
            queue_m2a: VecDeque::new(),
            a2m_inputs: Vec::new(),
            a2m_adjust: Vec::new(),
            m2a_inputs: Vec::new(),
            m2a_adjust: Vec::new(),
            _pd: PhantomData,
        }
    }

    /// Returns a reference to the ROLE sender.
    pub fn role(&self) -> &T {
        &self.role
    }

    /// Returns a mutable reference to the ROLE sender.
    pub fn role_mut(&mut self) -> &mut T {
        &mut self.role
    }

    /// Returns the inner OLE sender.
    pub fn into_inner(self) -> T {
        self.role
    }
}

impl<T, F> Sender<T, F>
where
    T: ROLESender<F>,
    F: Field,
{
    /// Returns `true` if the sender wants to flush.
    pub fn wants_flush(&self) -> bool {
        self.wants_a2m() || self.wants_m2a()
    }

    /// Returns `true` if the sender wants A2M.
    pub fn wants_a2m(&self) -> bool {
        !self.a2m_inputs.is_empty()
    }

    /// Returns `true` if the sender wants M2A.
    pub fn wants_m2a(&self) -> bool {
        !self.m2a_inputs.is_empty()
    }

    /// Sends A2M message.
    pub fn send_a2m(&mut self) -> Result<SendA2M<F>, SenderError> {
        let count = self.a2m_adjust.len();
        let mut outputs = Vec::with_capacity(count);
        let mut masked_shares = Vec::with_capacity(count);
        for adjust in self.a2m_adjust.drain(..) {
            let (output, masked) = adjust.send()?;
            outputs.push(output);
            masked_shares.push(masked);
        }

        let mut outputs = outputs.into_iter();
        for QueuedA2M { count, sender } in self.queue_a2m.drain(..) {
            let shares = outputs.by_ref().take(count).collect();
            sender.send(A2MOutput { shares });
        }

        Ok(SendA2M { masked_shares })
    }

    /// Receives A2M message.
    pub fn recv_a2m(&mut self, recv: RecvA2M<F>) -> Result<(), SenderError> {
        let RecvA2M { offsets } = recv;

        if self.a2m_inputs.len() != offsets.len() {
            return Err(SenderError(ErrorRepr::WrongA2MCount {
                expected: self.a2m_inputs.len(),
                actual: offsets.len(),
            }));
        }

        let count = self.a2m_inputs.len();
        let ROLESenderOutput { shares, .. } =
            self.role.try_send_role(count).map_err(SenderError::ole)?;

        self.a2m_adjust.extend(
            self.a2m_inputs
                .drain(..)
                .zip(shares)
                .zip(offsets)
                .map(|((input, share), offset)| A2MSenderDerand::new(input, share).offset(offset)),
        );

        Ok(())
    }

    /// Sends M2A message.
    pub fn send_m2a(&mut self) -> Result<SendM2A<F>, SenderError> {
        let count = self.m2a_inputs.len();

        let ROLESenderOutput { shares, .. } =
            self.role.try_send_role(count).map_err(SenderError::ole)?;

        self.m2a_adjust.reserve(count);
        let mut offsets = Vec::with_capacity(count);

        for (input, share) in self.m2a_inputs.drain(..).zip(shares) {
            let adjust = share.adjust(input);
            offsets.push(adjust.offset());
            self.m2a_adjust.push(adjust);
        }

        Ok(SendM2A { offsets })
    }

    /// Receives M2A message.
    pub fn recv_m2a(&mut self, recv: RecvM2A<F>) -> Result<(), SenderError> {
        let RecvM2A { offsets } = recv;

        if offsets.len() != self.m2a_adjust.len() {
            return Err(SenderError(ErrorRepr::WrongM2ACount {
                expected: self.m2a_adjust.len(),
                actual: offsets.len(),
            }));
        }

        let mut offsets = offsets.into_iter();
        let mut adjust = self.m2a_adjust.drain(..);
        for QueuedM2A { count, sender } in self.queue_m2a.drain(..) {
            let shares = offsets
                .by_ref()
                .take(count)
                .zip(adjust.by_ref())
                .map(|(offset, adjust)| adjust.sender_finish(offset).add)
                .collect();

            sender.send(M2AOutput { shares });
        }

        Ok(())
    }
}

impl<T, F> AdditiveToMultiplicative<F> for Sender<T, F>
where
    T: ROLESender<F>,
    F: Field,
{
    type Error = SenderError;
    type Future = MaybeDone<A2MOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.role.alloc(count).map_err(SenderError::ole)
    }

    fn queue_to_multiplicative(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.a2m_inputs.extend_from_slice(inputs);
        self.queue_a2m.push_back(QueuedA2M {
            count: inputs.len(),
            sender,
        });

        Ok(recv)
    }
}

impl<T, F> MultiplicativeToAdditive<F> for Sender<T, F>
where
    T: ROLESender<F>,
    F: Field,
{
    type Error = SenderError;
    type Future = MaybeDone<M2AOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.role.alloc(count).map_err(SenderError::ole)
    }

    fn queue_to_additive(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.m2a_inputs.extend_from_slice(inputs);
        self.queue_m2a.push_back(QueuedM2A {
            count: inputs.len(),
            sender,
        });

        Ok(recv)
    }
}

/// Error for [`Sender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SenderError(#[from] ErrorRepr);

impl SenderError {
    fn ole<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ole(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("OLE error: {0}")]
    Ole(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    A2M(#[from] A2MError),
    #[error("receiver sent wrong A2M count: expected {expected}, actual {actual}")]
    WrongA2MCount { expected: usize, actual: usize },
    #[error("receiver sent wrong M2A count: expected {expected}, actual {actual}")]
    WrongM2ACount { expected: usize, actual: usize },
}

impl From<A2MError> for SenderError {
    fn from(value: A2MError) -> Self {
        Self(ErrorRepr::A2M(value))
    }
}
