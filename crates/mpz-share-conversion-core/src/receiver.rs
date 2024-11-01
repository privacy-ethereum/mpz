//! Share conversion receiver.

//! Share conversion sender.

use std::{collections::VecDeque, marker::PhantomData};

use mpz_common::future::{new_output, MaybeDone, Sender as OutputSender};
use mpz_fields::Field;
use mpz_ole_core::{Adjust, ROLEReceiver, ROLEReceiverOutput};

use crate::{
    a2m::{A2MReceiverAdjust, A2MReceiverDerand},
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

/// Receiver for share conversion.
#[derive(Debug)]
pub struct Receiver<T, F> {
    role: T,
    queue_a2m: VecDeque<QueuedA2M<F>>,
    queue_m2a: VecDeque<QueuedM2A<F>>,
    a2m_inputs: Vec<F>,
    a2m_adjust: Vec<A2MReceiverAdjust<F>>,
    m2a_inputs: Vec<F>,
    m2a_adjust: Vec<Adjust<F>>,
    _pd: PhantomData<F>,
}

impl<T, F> Receiver<T, F> {
    /// Creates a new receiver.
    ///
    /// # Arguments
    ///
    /// * `role` - ROLE receiver.
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

    /// Returns a reference to the ROLE receiver.
    pub fn role(&self) -> &T {
        &self.role
    }

    /// Returns a mutable reference to the ROLE receiver.
    pub fn role_mut(&mut self) -> &mut T {
        &mut self.role
    }

    /// Returns the inner OLE receiver.
    pub fn into_inner(self) -> T {
        self.role
    }
}

impl<T, F> Receiver<T, F>
where
    T: ROLEReceiver<F>,
    F: Field,
{
    /// Returns `true` if the receiver wants to flush.
    pub fn wants_flush(&self) -> bool {
        self.wants_a2m() || self.wants_m2a()
    }

    /// Returns `true` if the receiver wants A2M.
    pub fn wants_a2m(&self) -> bool {
        !self.a2m_inputs.is_empty()
    }

    /// Returns `true` if the receiver wants M2A.
    pub fn wants_m2a(&self) -> bool {
        !self.m2a_inputs.is_empty()
    }

    /// Sends A2M message.
    pub fn send_a2m(&mut self) -> Result<RecvA2M<F>, ReceiverError> {
        let count = self.a2m_inputs.len();

        let ROLEReceiverOutput { shares, .. } =
            self.role.try_recv_role(count).map_err(ReceiverError::ole)?;

        self.a2m_adjust.reserve(count);
        let mut offsets = Vec::with_capacity(count);

        for (input, share) in self.a2m_inputs.drain(..).zip(shares) {
            let (adjust, offset) = A2MReceiverDerand::new(input, share).offset();
            offsets.push(offset);
            self.a2m_adjust.push(adjust);
        }

        Ok(RecvA2M { offsets })
    }

    /// Receives A2M message.
    pub fn recv_a2m(&mut self, send: SendA2M<F>) -> Result<(), ReceiverError> {
        let SendA2M { masked_shares } = send;
        let count = self.a2m_adjust.len();

        if masked_shares.len() != count {
            return Err(ReceiverError(ErrorRepr::WrongA2MCount {
                expected: count,
                actual: masked_shares.len(),
            }));
        }

        let mut outputs = Vec::with_capacity(count);
        for (adjust, masked) in self.a2m_adjust.drain(..).zip(masked_shares) {
            outputs.push(adjust.receive(masked));
        }

        let mut outputs = outputs.into_iter();
        for QueuedA2M { count, sender } in self.queue_a2m.drain(..) {
            let shares = outputs.by_ref().take(count).collect();
            sender.send(A2MOutput { shares });
        }

        Ok(())
    }

    /// Sends M2A message.
    pub fn send_m2a(&mut self) -> Result<RecvM2A<F>, ReceiverError> {
        let count = self.m2a_inputs.len();

        let ROLEReceiverOutput { shares, .. } =
            self.role.try_recv_role(count).map_err(ReceiverError::ole)?;

        self.m2a_adjust.reserve(count);
        let mut offsets = Vec::with_capacity(count);

        for (input, share) in self.m2a_inputs.drain(..).zip(shares) {
            let adjust = share.adjust(input);
            offsets.push(adjust.offset());
            self.m2a_adjust.push(adjust);
        }

        Ok(RecvM2A { offsets })
    }

    /// Receives M2A message.
    pub fn recv_m2a(&mut self, send: SendM2A<F>) -> Result<(), ReceiverError> {
        let SendM2A { offsets } = send;

        if offsets.len() != self.m2a_adjust.len() {
            return Err(ReceiverError(ErrorRepr::WrongM2ACount {
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
                .map(|(offset, adjust)| adjust.receiver_finish(offset).add)
                .collect();

            sender.send(M2AOutput { shares });
        }

        Ok(())
    }
}

impl<T, F> AdditiveToMultiplicative<F> for Receiver<T, F>
where
    T: ROLEReceiver<F>,
    F: Field,
{
    type Error = ReceiverError;
    type Future = MaybeDone<A2MOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.role.alloc(count).map_err(ReceiverError::ole)
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

impl<T, F> MultiplicativeToAdditive<F> for Receiver<T, F>
where
    T: ROLEReceiver<F>,
    F: Field,
{
    type Error = ReceiverError;
    type Future = MaybeDone<M2AOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.role.alloc(count).map_err(ReceiverError::ole)
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

/// Error for [`Receiver`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ReceiverError(#[from] ErrorRepr);

impl ReceiverError {
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
    #[error("sender sent wrong A2M count: expected {expected}, actual {actual}")]
    WrongA2MCount { expected: usize, actual: usize },
    #[error("sender sent wrong M2A count: expected {expected}, actual {actual}")]
    WrongM2ACount { expected: usize, actual: usize },
}
