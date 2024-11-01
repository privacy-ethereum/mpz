//! Ideal share conversion functionality.

use std::{
    collections::VecDeque,
    mem,
    sync::{Arc, Mutex},
};

use mpz_common::future::{new_output, MaybeDone, Sender};
use mpz_core::{prg::Prg, Block};
use mpz_fields::Field;

use crate::{A2MOutput, AdditiveToMultiplicative, M2AOutput, MultiplicativeToAdditive};

type Error = IdealShareConvertError;
type Result<T, E = Error> = core::result::Result<T, E>;

/// Create a pair of ideal share converters.
pub fn ideal_share_convert<F>(
    seed: Block,
) -> (IdealShareConvertSender<F>, IdealShareConvertReceiver<F>) {
    let prg = Prg::new_with_seed(seed.to_bytes());
    let inner = Inner {
        prg,
        sender_state: State::default(),
        receiver_state: State::default(),
    };
    let inner = Arc::new(Mutex::new(inner));
    (
        IdealShareConvertSender {
            inner: inner.clone(),
        },
        IdealShareConvertReceiver { inner },
    )
}

#[derive(Debug)]
struct QueuedA2M<F> {
    count: usize,
    sender: Sender<A2MOutput<F>>,
}

#[derive(Debug)]
struct QueuedM2A<F> {
    count: usize,
    sender: Sender<M2AOutput<F>>,
}

#[derive(Debug)]
struct State<F> {
    a2m_alloc: usize,
    a2m_queue: VecDeque<QueuedA2M<F>>,
    a2m_inputs: Vec<F>,
    m2a_alloc: usize,
    m2a_queue: VecDeque<QueuedM2A<F>>,
    m2a_inputs: Vec<F>,
}

impl<F> Default for State<F> {
    fn default() -> Self {
        Self {
            a2m_alloc: 0,
            a2m_queue: VecDeque::new(),
            a2m_inputs: Vec::new(),
            m2a_alloc: 0,
            m2a_queue: VecDeque::new(),
            m2a_inputs: Vec::new(),
        }
    }
}

/// Ideal share converter sender.
#[derive(Debug)]
pub struct IdealShareConvertSender<F> {
    inner: Arc<Mutex<Inner<F>>>,
}

impl<F> IdealShareConvertSender<F>
where
    F: Field,
{
    /// Returns `true` if the functionality wants to flush.
    pub fn wants_flush(&self) -> bool {
        self.inner.lock().unwrap().wants_flush()
    }

    /// Flushes the functionality.
    pub fn flush(&mut self) -> Result<()> {
        self.inner.lock().unwrap().flush()
    }
}

/// Ideal share converter receiver.
#[derive(Debug)]
pub struct IdealShareConvertReceiver<F> {
    inner: Arc<Mutex<Inner<F>>>,
}

impl<F> IdealShareConvertReceiver<F>
where
    F: Field,
{
    /// Returns `true` if the functionality wants to flush.
    pub fn wants_flush(&self) -> bool {
        self.inner.lock().unwrap().wants_flush()
    }

    /// Flushes the functionality.
    pub fn flush(&mut self) -> Result<()> {
        self.inner.lock().unwrap().flush()
    }
}

#[derive(Debug)]
struct Inner<F> {
    prg: Prg,
    sender_state: State<F>,
    receiver_state: State<F>,
}

impl<F> Inner<F>
where
    F: Field,
{
    fn wants_flush(&self) -> bool {
        let sender_a2m_queue = self.sender_state.a2m_queue.len();
        let sender_m2a_queue = self.sender_state.m2a_queue.len();
        let receiver_a2m_queue = self.receiver_state.a2m_queue.len();
        let receiver_m2a_queue = self.receiver_state.m2a_queue.len();

        let wants_a2m = sender_a2m_queue > 0
            && receiver_a2m_queue > 0
            && sender_a2m_queue == receiver_a2m_queue;
        let wants_m2a = sender_m2a_queue > 0
            && receiver_m2a_queue > 0
            && sender_m2a_queue == receiver_m2a_queue;

        wants_a2m || wants_m2a
    }

    fn flush(&mut self) -> Result<()> {
        if !self.wants_flush() {
            return Err(Error::new("not ready to flush".to_string()));
        } else if self.sender_state.a2m_alloc != self.receiver_state.a2m_alloc {
            return Err(Error::new(format!(
                "A2M alloc mismatch: sender={}, receiver={}",
                self.sender_state.a2m_alloc, self.receiver_state.a2m_alloc
            )));
        } else if self.sender_state.m2a_alloc != self.receiver_state.m2a_alloc {
            return Err(Error::new(format!(
                "M2A alloc mismatch: sender={}, receiver={}",
                self.sender_state.m2a_alloc, self.receiver_state.m2a_alloc
            )));
        }

        let sender_a2m_inputs = mem::take(&mut self.sender_state.a2m_inputs);
        let sender_m2a_inputs = mem::take(&mut self.sender_state.m2a_inputs);
        let receiver_a2m_inputs = mem::take(&mut self.receiver_state.a2m_inputs);
        let receiver_m2a_inputs = mem::take(&mut self.receiver_state.m2a_inputs);

        let sender_a2m_outputs: Vec<F> = (0..sender_a2m_inputs.len())
            .map(|_| F::rand(&mut self.prg))
            .collect();
        let receiver_a2m_outputs: Vec<_> = receiver_a2m_inputs
            .iter()
            .zip(&sender_a2m_inputs)
            .zip(&sender_a2m_outputs)
            .map(|((&x, &y), &a)| (x + y) * a.inverse().expect("a is not 0"))
            .collect();
        let sender_m2a_outputs: Vec<F> = (0..sender_m2a_inputs.len())
            .map(|_| F::rand(&mut self.prg))
            .collect();
        let receiver_m2a_outputs: Vec<_> = receiver_m2a_inputs
            .iter()
            .zip(&sender_m2a_inputs)
            .zip(&sender_m2a_outputs)
            .map(|((&a, &b), &x)| (a * b) - x)
            .collect();

        let mut i = 0;
        for QueuedA2M { count, sender } in self.sender_state.a2m_queue.drain(..) {
            let shares = sender_a2m_outputs[i..i + count].to_vec();
            i += count;
            sender.send(A2MOutput { shares });
        }

        i = 0;
        for QueuedA2M { count, sender } in self.receiver_state.a2m_queue.drain(..) {
            let shares = receiver_a2m_outputs[i..i + count].to_vec();
            i += count;
            sender.send(A2MOutput { shares });
        }

        i = 0;
        for QueuedM2A { count, sender } in self.sender_state.m2a_queue.drain(..) {
            let shares = sender_m2a_outputs[i..i + count].to_vec();
            i += count;
            sender.send(M2AOutput { shares });
        }

        i = 0;
        for QueuedM2A { count, sender } in self.receiver_state.m2a_queue.drain(..) {
            let shares = receiver_m2a_outputs[i..i + count].to_vec();
            i += count;
            sender.send(M2AOutput { shares });
        }

        self.sender_state.a2m_alloc = 0;
        self.sender_state.m2a_alloc = 0;
        self.receiver_state.a2m_alloc = 0;
        self.receiver_state.m2a_alloc = 0;

        Ok(())
    }
}

impl<F> AdditiveToMultiplicative<F> for IdealShareConvertSender<F>
where
    F: Field,
{
    type Error = Error;
    type Future = MaybeDone<A2MOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut this = self.inner.lock().unwrap();
        this.sender_state.a2m_alloc = count;
        Ok(())
    }

    fn queue_to_multiplicative(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        let mut this = self.inner.lock().unwrap();

        let (sender, recv) = new_output();

        let count = inputs.len();
        this.sender_state.a2m_inputs.extend_from_slice(inputs);
        this.sender_state
            .a2m_queue
            .push_back(QueuedA2M { count, sender });

        Ok(recv)
    }
}

impl<F> MultiplicativeToAdditive<F> for IdealShareConvertSender<F>
where
    F: Field,
{
    type Error = Error;
    type Future = MaybeDone<M2AOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut this = self.inner.lock().unwrap();
        this.sender_state.m2a_alloc = count;
        Ok(())
    }

    fn queue_to_additive(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        let mut this = self.inner.lock().unwrap();

        let (sender, recv) = new_output();

        let count = inputs.len();
        this.sender_state.m2a_inputs.extend_from_slice(inputs);
        this.sender_state
            .m2a_queue
            .push_back(QueuedM2A { count, sender });

        Ok(recv)
    }
}

impl<F> AdditiveToMultiplicative<F> for IdealShareConvertReceiver<F>
where
    F: Field,
{
    type Error = Error;
    type Future = MaybeDone<A2MOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut this = self.inner.lock().unwrap();
        this.receiver_state.a2m_alloc = count;
        Ok(())
    }

    fn queue_to_multiplicative(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        let mut this = self.inner.lock().unwrap();

        let (sender, recv) = new_output();

        let count = inputs.len();
        this.receiver_state.a2m_inputs.extend_from_slice(inputs);
        this.receiver_state
            .a2m_queue
            .push_back(QueuedA2M { count, sender });

        Ok(recv)
    }
}

impl<F> MultiplicativeToAdditive<F> for IdealShareConvertReceiver<F>
where
    F: Field,
{
    type Error = Error;
    type Future = MaybeDone<M2AOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        let mut this = self.inner.lock().unwrap();
        this.receiver_state.m2a_alloc = count;
        Ok(())
    }

    fn queue_to_additive(&mut self, inputs: &[F]) -> Result<Self::Future, Self::Error> {
        let mut this = self.inner.lock().unwrap();

        let (sender, recv) = new_output();

        let count = inputs.len();
        this.receiver_state.m2a_inputs.extend_from_slice(inputs);
        this.receiver_state
            .m2a_queue
            .push_back(QueuedM2A { count, sender });

        Ok(recv)
    }
}

/// Error for [`IdealShareConvert`].
#[derive(Debug, thiserror::Error)]
#[error("ideal share convert error: {0}")]
pub struct IdealShareConvertError(String);

impl IdealShareConvertError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use mpz_common::future::Output;
    use mpz_fields::{gf2_128::Gf2_128, p256::P256};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn test_ideal_convert_p256() {
        test_ideal_convert::<P256>();
    }

    #[test]
    fn test_ideal_convert_gf2_128() {
        test_ideal_convert::<Gf2_128>();
    }

    fn test_ideal_convert<F: Field>() {
        let mut rng = StdRng::seed_from_u64(0);
        let (mut sender, mut receiver) = ideal_share_convert::<F>(Block::random(&mut rng));

        let count = 10;
        AdditiveToMultiplicative::alloc(&mut sender, count).unwrap();
        MultiplicativeToAdditive::alloc(&mut sender, count).unwrap();
        AdditiveToMultiplicative::alloc(&mut receiver, count).unwrap();
        MultiplicativeToAdditive::alloc(&mut receiver, count).unwrap();

        let sender_inputs: Vec<_> = (0..count).map(|_| F::rand(&mut rng)).collect();
        let receiver_inputs: Vec<_> = (0..count).map(|_| F::rand(&mut rng)).collect();

        let mut sender_a2m = sender.queue_to_multiplicative(&sender_inputs).unwrap();
        let mut receiver_a2m = receiver.queue_to_multiplicative(&receiver_inputs).unwrap();
        let mut sender_m2a = sender.queue_to_additive(&sender_inputs).unwrap();
        let mut receiver_m2a = receiver.queue_to_additive(&receiver_inputs).unwrap();

        assert!(sender.wants_flush());
        assert!(receiver.wants_flush());

        sender.flush().unwrap();

        assert!(!sender.wants_flush());
        assert!(!receiver.wants_flush());

        let sender_a2m_output = sender_a2m.try_recv().unwrap().unwrap();
        let receiver_a2m_output = receiver_a2m.try_recv().unwrap().unwrap();
        let sender_m2a_output = sender_m2a.try_recv().unwrap().unwrap();
        let receiver_m2a_output = receiver_m2a.try_recv().unwrap().unwrap();

        for i in 0..count {
            assert_eq!(
                sender_a2m_output.shares[i] * receiver_a2m_output.shares[i],
                sender_inputs[i] + receiver_inputs[i]
            );
            assert_eq!(
                sender_m2a_output.shares[i] + receiver_m2a_output.shares[i],
                sender_inputs[i] * receiver_inputs[i]
            );
        }
    }
}
