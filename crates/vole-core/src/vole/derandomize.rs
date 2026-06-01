use std::{collections::VecDeque, marker::PhantomData, mem};

use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_fields::{ExtensionField, Field};
use serde::{Deserialize, Serialize};

use super::{VOLEReceiver, VOLEReceiverOutput};
use crate::rvole::RVOLEReceiver;

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

        let queued_total: usize = queue.iter().map(|q| q.count).sum();
        if queued_total != targets.len() {
            return Err(DerandVOLEReceiverError::InternalInconsistency {
                targets: targets.len(),
                queued: queued_total,
            });
        }

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

    /// Target buffer and queue count disagreed.
    #[error("internal inconsistency: {targets} targets buffered but queue sums to {queued} items")]
    InternalInconsistency {
        /// Number of buffered targets.
        targets: usize,
        /// Sum of queued counts.
        queued: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        ideal::rvole::ideal_rvole,
        rvole::{RVOLESender, RVOLESenderOutput},
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

        // Verify the VOLE invariant per chunk:
        // the sender rotates key_new[j] = key_rand[j] - diff[j]·Δ
        // (char-2: - == +), and the chunk's mac must equal
        // key_new + Δ · target.
        let mut diff_cursor = 0;
        for ((batch, out), (ts, &n)) in sender_batches
            .iter()
            .zip(&outs)
            .zip(targets.iter().zip(SIZES.iter()))
        {
            let chunk_diffs = &adjustment.diffs[diff_cursor..diff_cursor + n];
            diff_cursor += n;

            for j in 0..n {
                let key_rand = batch.keys[j];
                let key_new = key_rand + chunk_diffs[j] * delta;
                let expected_mac = key_new + delta * Gf2_128::embed(ts[j]);
                assert_eq!(
                    out.macs[j], expected_mac,
                    "invariant violated in chunk of size {n} at position {j}",
                );
            }
        }
    }
}
