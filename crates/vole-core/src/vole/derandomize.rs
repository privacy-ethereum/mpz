use std::{collections::VecDeque, marker::PhantomData, mem};

use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_fields::{ExtensionField, Field};
use serde::{Deserialize, Serialize};

use super::{VOLEReceiver, VOLEReceiverOutput};
use crate::rvole::{RVOLEReceiver, RVOLESender};

/// VOLE adjustment message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoleAdjustment<E: Field> {
    /// Differences between target and random values, embedded in `E`.
    pub diffs: Vec<E>,
}

#[derive(Debug)]
struct QueuedReceive<E: Field> {
    count: usize,
    sender: Sender<VOLEReceiverOutput<E>>,
}

/// Derandomized VOLE receiver.
///
/// This is a VOLE receiver which derandomizes preprocessed RVOLEs.
/// Parameterized over base field `W` and extension `E: ExtensionField<W>`;
/// its values live in `W`, its MACs in `E`, and the correlation is
/// `mac = key + delta · E::embed(value)`. Full-field VOLE is the special
/// case `W = E`.
pub struct DerandVOLEReceiver<T, W, E>
where
    T: RVOLEReceiver<W, E>,
    W: Field,
    E: ExtensionField<W>,
{
    rvole: T,
    /// Target values which need to be derandomized.
    targets: Vec<W>,
    queue: VecDeque<QueuedReceive<E>>,
    _phantom: PhantomData<(W, E)>,
}

impl<T, W, E> DerandVOLEReceiver<T, W, E>
where
    T: RVOLEReceiver<W, E>,
    W: Field,
    E: ExtensionField<W>,
{
    /// Creates a new `DerandVOLEReceiver`.
    pub fn new(rvole: T) -> Self {
        Self {
            rvole,
            targets: Vec::new(),
            queue: VecDeque::new(),
            _phantom: PhantomData,
        }
    }

    /// Returns a reference to the RVOLE receiver.
    pub fn rvole(&self) -> &T {
        &self.rvole
    }

    /// Returns a mutable reference to the RVOLE receiver.
    pub fn rvole_mut(&mut self) -> &mut T {
        &mut self.rvole
    }

    /// Returns the inner RVOLE receiver.
    pub fn into_inner(self) -> T {
        self.rvole
    }

    /// Returns `true` if the receiver wants to adjust VOLEs.
    pub fn wants_adjust(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Returns the adjustment message.
    pub fn adjust(&mut self) -> Result<VoleAdjustment<E>, DerandVOLEReceiverError> {
        let targets = mem::take(&mut self.targets);
        let queue = mem::take(&mut self.queue);

        debug_assert_eq!(
            queue.iter().map(|q| q.count).sum::<usize>(),
            targets.len(),
            "targets buffer desynced from queue count sum",
        );

        let mut diffs: Vec<E> = Vec::with_capacity(targets.len());
        let mut i = 0;

        for QueuedReceive { count, sender } in queue {
            let rvole_out = self
                .rvole
                .try_recv_vole(count)
                .map_err(|e| DerandVOLEReceiverError::Inner(Box::new(e)))?;

            for j in 0..count {
                let d = E::embed(targets[i + j]) - E::embed(rvole_out.values[j]);
                diffs.push(d);
            }
            i += count;

            sender.send(VOLEReceiverOutput {
                id: rvole_out.id,
                macs: rvole_out.macs,
            });
        }

        Ok(VoleAdjustment { diffs })
    }
}

impl<T, W, E> VOLEReceiver<W, E> for DerandVOLEReceiver<T, W, E>
where
    T: RVOLEReceiver<W, E>,
    W: Field,
    E: ExtensionField<W>,
{
    type Error = DerandVOLEReceiverError;
    type Future = MaybeDone<VOLEReceiverOutput<E>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.rvole
            .alloc(count)
            .map_err(|e| DerandVOLEReceiverError::Inner(Box::new(e)))
    }

    fn available(&self) -> usize {
        self.rvole.available()
    }

    fn queue_recv_vole(&mut self, values: &[W]) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output::<VOLEReceiverOutput<E>>();
        self.targets.extend_from_slice(values);
        self.queue.push_back(QueuedReceive {
            count: values.len(),
            sender,
        });
        Ok(recv)
    }
}

/// Error for [`DerandVOLEReceiver`].
#[derive(Debug, thiserror::Error)]
pub enum DerandVOLEReceiverError {
    /// Inner RVOLE receiver error.
    #[error("inner RVOLE receiver error: {0}")]
    Inner(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Derandomized VOLE sender.
///
/// Counterpart to [`DerandVOLEReceiver`]. Wraps an [`RVOLESender`]; on
/// receipt of a [`VoleAdjustment`] from the receiver, derives the
/// derandomized keys via `K_new[j] = k_rand[j] − diffs[j] · Δ`. The
/// resulting `(K_new, m_r)` pair satisfies the IT-MAC relation
/// `m_r = K_new + Δ · E::embed(v)` for the receiver's chosen value `v`.
pub struct DerandVOLESender<T, E>
where
    T: RVOLESender<E>,
    E: Field,
{
    rvole: T,
    _phantom: PhantomData<E>,
}

impl<T, E> DerandVOLESender<T, E>
where
    T: RVOLESender<E>,
    E: Field,
{
    /// Creates a new `DerandVOLESender`.
    pub fn new(rvole: T) -> Self {
        Self {
            rvole,
            _phantom: PhantomData,
        }
    }

    /// Returns a reference to the RVOLE sender.
    pub fn rvole(&self) -> &T {
        &self.rvole
    }

    /// Returns a mutable reference to the RVOLE sender.
    pub fn rvole_mut(&mut self) -> &mut T {
        &mut self.rvole
    }

    /// Returns the inner RVOLE sender.
    pub fn into_inner(self) -> T {
        self.rvole
    }

    /// Allocates `count` RVOLEs in the underlying sender.
    pub fn alloc(&mut self, count: usize) -> Result<(), DerandVOLESenderError> {
        self.rvole
            .alloc(count)
            .map_err(|e| DerandVOLESenderError::Inner(Box::new(e)))
    }

    /// Number of preprocessed RVOLEs available in the underlying sender.
    pub fn available(&self) -> usize {
        self.rvole.available()
    }

    /// Returns the global correlation key, `Δ`.
    pub fn delta(&self) -> E {
        self.rvole.delta()
    }

    /// Consume a [`VoleAdjustment`], returning the derandomized keys.
    pub fn adjust(
        &mut self,
        adjustment: &VoleAdjustment<E>,
    ) -> Result<Vec<E>, DerandVOLESenderError> {
        let n = adjustment.diffs.len();
        let raw = self
            .rvole
            .try_send_vole(n)
            .map_err(|e| DerandVOLESenderError::Inner(Box::new(e)))?;
        let delta = self.rvole.delta();
        Ok((0..n)
            .map(|j| raw.keys[j] - adjustment.diffs[j] * delta)
            .collect())
    }
}

/// Error for [`DerandVOLESender`].
#[derive(Debug, thiserror::Error)]
pub enum DerandVOLESenderError {
    /// Inner RVOLE sender error.
    #[error("inner RVOLE sender error: {0}")]
    Inner(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        ideal::rvole::ideal_rvole,
        rvole::{RVOLESender, RVOLESenderOutput},
        test::assert_vole,
    };
    use mpz_common::future::Output;
    use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
    use rand::{Rng, SeedableRng, rngs::SmallRng};

    /// Queues three `queue_recv_vole` calls with distinct lengths and
    /// asserts that `adjust` splits the accumulated targets across them
    /// exactly by count, in FIFO order — each future resolves with the
    /// MACs correlated to its chunk, and the diffs line up positionally.
    #[test]
    fn test_adjust_splits_multi_queue_by_length() {
        let mut rng = SmallRng::seed_from_u64(0xDEAD_BEEF);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();

        // RVOLE pool sized exactly for the three queued batches.
        let (mut sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);
        const SIZES: [usize; 3] = [3, 5, 2];
        const TOTAL: usize = 10; // SIZES.iter().sum() but const at call sites below
        sender.pregenerate(TOTAL);
        receiver.pregenerate(TOTAL, delta).unwrap();

        let mut derand = DerandVOLEReceiver::new(receiver);

        // Three target batches of different lengths.
        let targets: Vec<Vec<Gf2>> = SIZES
            .iter()
            .map(|&n| (0..n).map(|_| rng.random()).collect())
            .collect();

        let mut futs: Vec<_> = targets
            .iter()
            .map(|t| derand.queue_recv_vole(t).unwrap())
            .collect();

        // Before adjust: nothing resolved.
        for fut in &mut futs {
            assert!(matches!(fut.try_recv(), Ok(None)));
        }

        let adjustment = derand.adjust().unwrap();
        assert_eq!(adjustment.diffs.len(), TOTAL);

        // Each future resolved with the right mac count, in FIFO order.
        let outs: Vec<_> = futs
            .iter_mut()
            .map(|f| f.try_recv().unwrap().expect("resolved"))
            .collect();
        for (out, &n) in outs.iter().zip(SIZES.iter()) {
            assert_eq!(out.macs.len(), n);
        }

        // Sender consumes its pool in matching chunks so its keys line
        // up positionally with the receiver's LIFO-chunk consumption.
        let sender_batches: Vec<RVOLESenderOutput<Gf2_128>> = SIZES
            .iter()
            .map(|&n| sender.try_send_vole(n).unwrap())
            .collect();

        // Sender derandomizes via key_new[j] = key_rand[j] - diff[j]·Δ;
        // check the IT-MAC relation against the receiver's MACs per chunk.
        let mut diff_cursor = 0;
        for (((batch, out), ts), &n) in sender_batches
            .iter()
            .zip(&outs)
            .zip(targets.iter())
            .zip(SIZES.iter())
        {
            let chunk_diffs = &adjustment.diffs[diff_cursor..diff_cursor + n];
            diff_cursor += n;

            let keys_new: Vec<Gf2_128> = (0..n)
                .map(|j| batch.keys[j] - chunk_diffs[j] * delta)
                .collect();
            assert_vole(delta, &keys_new, ts, &out.macs);
        }
    }

    /// Pairs `DerandVOLEReceiver` with `DerandVOLESender` end-to-end.
    #[test]
    fn sender_adjust_satisfies_it_mac_relation() {
        let mut rng = SmallRng::seed_from_u64(0xA5A5_5A5A);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();

        const N: usize = 7;
        let (mut sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);
        sender.pregenerate(N);
        receiver.pregenerate(N, delta).unwrap();
        let mut derand_sender = DerandVOLESender::new(sender);
        let mut derand_receiver = DerandVOLEReceiver::new(receiver);

        // Receiver chooses targets and produces the adjustment.
        let targets: Vec<Gf2> = (0..N).map(|_| rng.random()).collect();
        let mut fut = derand_receiver.queue_recv_vole(&targets).unwrap();
        let adjustment = derand_receiver.adjust().unwrap();
        let macs = fut.try_recv().unwrap().expect("future resolved").macs;
        assert_eq!(macs.len(), N);

        // Sender consumes the adjustment to get rebased keys.
        let keys = derand_sender.adjust(&adjustment).unwrap();
        assert_eq!(keys.len(), N);

        // Each (K_new, m_r) pair must satisfy m_r = K_new + Δ · embed(v).
        assert_vole(delta, &keys, &targets, &macs);
    }

    /// `wants_adjust` is false on a fresh receiver, true once any batch
    /// has been queued, and back to false after `adjust` drains the queue.
    #[test]
    fn wants_adjust_lifecycle() {
        let mut rng = SmallRng::seed_from_u64(0xCAFE_F00D);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();
        let (_sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);
        receiver.pregenerate(4, delta).unwrap();
        let mut derand = DerandVOLEReceiver::new(receiver);

        assert!(!derand.wants_adjust());
        let targets: Vec<Gf2> = (0..4).map(|_| rng.random()).collect();
        let _fut = derand.queue_recv_vole(&targets).unwrap();
        assert!(derand.wants_adjust());
        derand.adjust().unwrap();
        assert!(!derand.wants_adjust());
    }

    /// `adjust` on a receiver with nothing queued returns an empty
    /// adjustment and does not consume any preprocessed RVOLEs.
    #[test]
    fn receiver_adjust_empty_is_noop() {
        let mut rng = SmallRng::seed_from_u64(0xF00D_BEEF);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();
        let (_sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);
        receiver.pregenerate(8, delta).unwrap();
        let mut derand = DerandVOLEReceiver::new(receiver);

        let before = derand.available();
        let adjustment = derand.adjust().unwrap();
        assert!(adjustment.diffs.is_empty());
        assert_eq!(derand.available(), before);
    }

    /// `adjust` on a sender given an empty adjustment returns no keys
    /// and does not consume any preprocessed RVOLEs.
    #[test]
    fn sender_adjust_empty_is_noop() {
        let mut rng = SmallRng::seed_from_u64(0xBEEF_CAFE);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();
        let (mut sender, _receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);
        sender.pregenerate(8);
        let mut derand = DerandVOLESender::new(sender);

        let before = derand.available();
        let empty: VoleAdjustment<Gf2_128> = VoleAdjustment { diffs: Vec::new() };
        let keys = derand.adjust(&empty).unwrap();
        assert!(keys.is_empty());
        assert_eq!(derand.available(), before);
    }

    /// Queue → adjust → queue → adjust on the same receiver: round 2
    /// must not see contamination (stale targets, stale queue) from
    /// round 1, and both rounds must satisfy the IT-MAC relation.
    #[test]
    fn receiver_supports_multiple_rounds() {
        let mut rng = SmallRng::seed_from_u64(0xD00D_FACE);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();
        const R1: usize = 3;
        const R2: usize = 4;
        let (mut sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);
        sender.pregenerate(R1 + R2);
        receiver.pregenerate(R1 + R2, delta).unwrap();
        let mut derand = DerandVOLEReceiver::new(receiver);

        // Round 1.
        let t1: Vec<Gf2> = (0..R1).map(|_| rng.random()).collect();
        let mut f1 = derand.queue_recv_vole(&t1).unwrap();
        let a1 = derand.adjust().unwrap();
        let o1 = f1.try_recv().unwrap().expect("resolved");
        assert_eq!(a1.diffs.len(), R1);
        assert_eq!(o1.macs.len(), R1);
        assert!(!derand.wants_adjust());

        // Round 2 — must see no contamination from round 1.
        let t2: Vec<Gf2> = (0..R2).map(|_| rng.random()).collect();
        let mut f2 = derand.queue_recv_vole(&t2).unwrap();
        let a2 = derand.adjust().unwrap();
        let o2 = f2.try_recv().unwrap().expect("resolved");
        assert_eq!(a2.diffs.len(), R2);
        assert_eq!(o2.macs.len(), R2);

        // IT-MAC holds independently in each round against the sender's
        // pool consumed in matching order.
        let b1 = sender.try_send_vole(R1).unwrap();
        let b2 = sender.try_send_vole(R2).unwrap();
        let k1_new: Vec<Gf2_128> = (0..R1)
            .map(|j| b1.keys[j] - a1.diffs[j] * delta)
            .collect();
        let k2_new: Vec<Gf2_128> = (0..R2)
            .map(|j| b2.keys[j] - a2.diffs[j] * delta)
            .collect();
        assert_vole(delta, &k1_new, &t1, &o1.macs);
        assert_vole(delta, &k2_new, &t2, &o2.macs);
    }

    /// If the inner RVOLE pool is short of what's been queued, the
    /// receiver's `adjust` surfaces the inner error wrapped in `Inner`.
    #[test]
    fn receiver_propagates_inner_error() {
        let mut rng = SmallRng::seed_from_u64(0x1234_5678);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();
        let (_sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);
        receiver.pregenerate(2, delta).unwrap(); // deliberately short
        let mut derand = DerandVOLEReceiver::new(receiver);

        let targets: Vec<Gf2> = (0..5).map(|_| rng.random()).collect();
        let _fut = derand.queue_recv_vole(&targets).unwrap();
        assert!(matches!(
            derand.adjust(),
            Err(DerandVOLEReceiverError::Inner(_))
        ));
    }

    /// Symmetric case on the sender: if the inner pool can't satisfy the
    /// adjustment's diff count, the error surfaces wrapped in `Inner`.
    #[test]
    fn sender_propagates_inner_error() {
        let mut rng = SmallRng::seed_from_u64(0x5678_1234);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();
        let (mut sender, _receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);
        sender.pregenerate(2); // deliberately short
        let mut derand = DerandVOLESender::new(sender);

        let diffs: Vec<Gf2_128> = (0..5).map(|_| rng.random()).collect();
        let adjustment = VoleAdjustment { diffs };
        assert!(matches!(
            derand.adjust(&adjustment),
            Err(DerandVOLESenderError::Inner(_))
        ));
    }
}
