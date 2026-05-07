//! Ideal VOLE functionality.
//!
//! This implementation uses message-based communication where the sender
//! produces a `FlushMsg` that the receiver consumes. Keys are generated
//! deterministically from a shared seed.

use std::mem;

use hybrid_array::Array;
use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_fields::{ExtensionField, Field};
use rand::{RngCore, SeedableRng, rngs::SmallRng};
use serde::{Deserialize, Serialize};

use crate::{
    VoleId,
    rvole::{RVOLESender, RVOLESenderOutput},
    vole::{VOLEReceiver, VOLEReceiverOutput},
};

/// Message sent from sender to receiver during flush.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushMsg<E: Field> {
    /// Base seed for key generation.
    pub seed: u64,
    /// Offset into the key sequence.
    pub offset: u64,
    /// Number of VOLEs to generate.
    pub count: usize,
    /// Global correlation delta.
    pub delta: E,
}

/// Generate keys deterministically from `(seed, offset)`.
fn generate_keys<E: Field>(seed: u64, offset: u64, count: usize) -> Vec<E> {
    let mut rng = SmallRng::seed_from_u64(seed.wrapping_add(offset));
    (0..count)
        .map(|_| {
            let mut buf: Array<u8, E::ByteSize> = Array::default();
            rng.fill_bytes(buf.as_mut_slice());
            E::try_from(buf).expect("uniform bytes should yield a valid field element")
        })
        .collect()
}

/// Returns a new ideal VOLE sender and receiver.
pub fn ideal_vole<W, E>(seed: u64, delta: E) -> (IdealVOLESender<E>, IdealVOLEReceiver<W, E>)
where
    W: Field,
    E: ExtensionField<W>,
{
    (
        IdealVOLESender::new(seed, delta),
        IdealVOLEReceiver::new(seed),
    )
}

/// Ideal VOLE sender.
#[derive(Debug)]
pub struct IdealVOLESender<E: Field> {
    seed: u64,
    delta: E,
    /// Current offset into key sequence.
    offset: u64,
    /// Pending allocation count.
    pending: usize,
    /// Generated keys.
    keys: Vec<E>,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<RVOLESenderOutput<E>>)>,
    /// VOLE ID counter.
    vole_id: VoleId,
    /// Sticky flag: once `pregenerate` has been called, `flush` stops
    /// generating. Under-sized pregeneration surfaces as an error on
    /// `try_send_vole` / `queue_send_vole`.
    pregenerated: bool,
}

impl<E: Field> IdealVOLESender<E> {
    /// Creates a new sender with the given seed and delta.
    pub fn new(seed: u64, delta: E) -> Self {
        Self {
            seed,
            delta,
            offset: 0,
            pending: 0,
            keys: Vec::new(),
            queue: Vec::new(),
            vole_id: VoleId::default(),
            pregenerated: false,
        }
    }

    /// Returns `true` if the sender wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        !self.pregenerated && (self.pending > 0 || !self.queue.is_empty())
    }

    /// Pre-generates `count` VOLE keys immediately.
    ///
    /// Bypasses the alloc/flush cycle: keys are materialized locally and
    /// pushed into the available pool. Intended for test/benchmark setup
    /// so the online consumption path does only bookkeeping.
    ///
    /// Once called, this sender is locked into pregenerated mode —
    /// `flush` becomes a no-op, and `try_send_vole` / `queue_send_vole`
    /// error with "not enough VOLEs" if the pool runs dry.
    pub fn pregenerate(&mut self, count: usize) {
        self.pregenerated = true;
        // Absorb any prior lazy-mode alloc intent — it's dead state
        // once we've committed to pregenerated mode.
        self.pending = 0;
        self.materialize(count);
        self.drain_queue();
    }

    /// Generates `count` keys from the current `(seed, offset)` and
    /// advances `offset`.
    fn materialize(&mut self, count: usize) {
        let new_keys = generate_keys::<E>(self.seed, self.offset, count);
        self.keys.extend(new_keys);
        self.offset = self.offset.wrapping_add(count as u64);
    }

    /// Fulfills any queued `queue_send_vole` requests that the pool can
    /// now satisfy.
    fn drain_queue(&mut self) {
        for (queued_count, qsender) in mem::take(&mut self.queue) {
            if self.keys.len() >= queued_count {
                let keys: Vec<E> = if queued_count == self.keys.len() {
                    mem::take(&mut self.keys)
                } else {
                    self.keys.drain(..queued_count).collect()
                };
                qsender.send(RVOLESenderOutput {
                    id: self.vole_id.next(),
                    keys,
                });
            }
        }
    }

    /// Flushes pending operations, returning the message to send to receiver.
    ///
    /// Returns `None` if there's nothing to flush, or if the sender is
    /// in pregenerated mode (the pool is owned by `pregenerate` alone).
    pub fn flush(&mut self) -> Option<FlushMsg<E>> {
        if self.pregenerated {
            return None;
        }
        if self.pending == 0 && self.queue.is_empty() {
            return None;
        }
        let count = self.pending;
        let current_offset = self.offset;

        if count > 0 {
            self.materialize(count);
            self.pending = 0;
        }

        self.drain_queue();

        if count > 0 {
            Some(FlushMsg {
                seed: self.seed,
                offset: current_offset,
                count,
                delta: self.delta,
            })
        } else {
            None
        }
    }
}

impl<E: Field> RVOLESender<E> for IdealVOLESender<E> {
    type Error = IdealVOLEError;
    type Future = MaybeDone<RVOLESenderOutput<E>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.pregenerated {
            return Ok(());
        }
        self.pending += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.keys.len()
    }

    fn delta(&self) -> E {
        self.delta
    }

    fn try_send_vole(&mut self, count: usize) -> Result<RVOLESenderOutput<E>, Self::Error> {
        if count > self.keys.len() {
            return Err(IdealVOLEError::new(format!(
                "not enough VOLEs: available={}, requested={}",
                self.keys.len(),
                count
            )));
        }
        // `drain(..len)` copies the whole buffer into a new vec —
        // non-negligible when element count is in the millions. When
        // consuming everything, swap the vec out for free instead.
        let keys: Vec<E> = if count == self.keys.len() {
            mem::take(&mut self.keys)
        } else {
            self.keys.drain(..count).collect()
        };
        Ok(RVOLESenderOutput {
            id: self.vole_id.next(),
            keys,
        })
    }

    fn queue_send_vole(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.pregenerated && count > self.keys.len() {
            return Err(IdealVOLEError::new(format!(
                "not enough pregenerated VOLEs: available={}, requested={}",
                self.keys.len(),
                count
            )));
        }
        let (send, recv) = new_output();
        if self.keys.len() >= count {
            // Same drain trap as `try_send_vole`; swap when consuming
            // everything.
            let keys: Vec<E> = if count == self.keys.len() {
                mem::take(&mut self.keys)
            } else {
                self.keys.drain(..count).collect()
            };
            send.send(RVOLESenderOutput {
                id: self.vole_id.next(),
                keys,
            });
        } else {
            self.queue.push((count, send));
        }
        Ok(recv)
    }
}

/// Ideal VOLE receiver.
#[derive(Debug)]
pub struct IdealVOLEReceiver<W, E: Field> {
    /// Shared seed (same as sender's).
    seed: u64,
    /// Current offset into the key sequence.
    offset: u64,
    /// Cached delta, learned at the first `pregenerate` or `flush` call.
    delta: Option<E>,
    /// Pending target values.
    pending_targets: Vec<W>,
    /// Pending allocation count.
    pending_alloc: usize,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<VOLEReceiverOutput<E>>)>,
    /// Materialized MACs.
    macs: Vec<E>,
    /// Materialized values.
    values: Vec<W>,
    /// VOLE ID counter.
    vole_id: VoleId,
    /// Sticky flag: once `pregenerate` has been called, `flush` stops
    /// generating. Under-sized pregeneration surfaces as an error on
    /// `queue_recv_vole`.
    pregenerated: bool,
}

impl<W, E> IdealVOLEReceiver<W, E>
where
    W: Field,
    E: ExtensionField<W>,
{
    /// Creates a new receiver with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            offset: 0,
            delta: None,
            pending_targets: Vec::new(),
            pending_alloc: 0,
            queue: Vec::new(),
            macs: Vec::new(),
            values: Vec::new(),
            vole_id: VoleId::default(),
            pregenerated: false,
        }
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        !self.pregenerated && (self.pending_alloc > 0 || !self.queue.is_empty())
    }

    /// Pre-computes MACs for the given `targets` immediately, using `delta`.
    ///
    /// The first call sets the cached delta; subsequent calls (and later
    /// flushes) must match it. Intended for test/benchmark setup so the
    /// online consumption path does only bookkeeping.
    ///
    /// Once called, this receiver is locked into pregenerated mode —
    /// `flush` becomes a no-op, and `queue_recv_vole` errors with
    /// "not enough VOLEs" if the pool runs dry.
    pub fn pregenerate(&mut self, targets: &[W], delta: E) -> Result<(), IdealVOLEError> {
        // Refuse to mix modes.
        if !self.pending_targets.is_empty() {
            return Err(IdealVOLEError::new(
                "cannot pregenerate: pending_targets is non-empty \
                 (lazy-mode queue_recv_vole already called)",
            ));
        }
        self.pregenerated = true;
        // Absorb any prior lazy-mode alloc intent — it's dead state
        // once we've committed to pregenerated mode.
        self.pending_alloc = 0;
        match self.delta {
            Some(existing) if existing != delta => {
                return Err(IdealVOLEError::new("delta mismatch in pregenerate"));
            }
            _ => self.delta = Some(delta),
        }

        let count = targets.len();
        self.materialize(self.seed, self.offset, targets, delta);
        self.offset = self.offset.wrapping_add(count as u64);
        self.drain_queue();

        Ok(())
    }

    /// Generates `targets.len()` keys from `(seed, offset)`, pairs them
    /// with `targets` to compute MACs against `delta`, and extends both
    /// pools. Does not advance `self.offset` — callers handle that
    /// depending on their seed/offset source.
    fn materialize(&mut self, seed: u64, offset: u64, targets: &[W], delta: E) {
        let keys = generate_keys::<E>(seed, offset, targets.len());
        let macs: Vec<E> = keys
            .iter()
            .zip(targets)
            .map(|(k, v)| *k + delta * E::embed(*v))
            .collect();
        self.values.extend_from_slice(targets);
        self.macs.extend(macs);
    }

    /// Fulfills any queued `queue_recv_vole` requests that the pool can
    /// now satisfy. Keeps `values` and `macs`
    /// in lockstep; only macs are shipped (the caller already has the
    /// values).
    fn drain_queue(&mut self) {
        for (queued_count, qsender) in mem::take(&mut self.queue) {
            if self.macs.len() >= queued_count {
                let macs: Vec<E> = if queued_count == self.macs.len() {
                    let _ = mem::take(&mut self.values);
                    mem::take(&mut self.macs)
                } else {
                    let _ = self
                        .values
                        .drain(..queued_count)
                        .collect::<Vec<_>>();
                    self.macs.drain(..queued_count).collect()
                };
                qsender.send(VOLEReceiverOutput {
                    id: self.vole_id.next(),
                    macs,
                });
            }
        }
    }

    /// Flushes pending operations using the message from the sender.
    pub fn flush(&mut self, flush_msg: FlushMsg<E>) -> Result<(), IdealVOLEError> {
        if self.pregenerated {
            return Ok(());
        }
        if flush_msg.count != self.pending_alloc {
            return Err(IdealVOLEError::new(format!(
                "count mismatch: expected={}, received={}",
                self.pending_alloc, flush_msg.count
            )));
        }
        if flush_msg.count > self.pending_targets.len() {
            return Err(IdealVOLEError::new(format!(
                "pending targets ({}) fewer than flushed count ({})",
                self.pending_targets.len(),
                flush_msg.count
            )));
        }
        if let Some(existing) = self.delta {
            if existing != flush_msg.delta {
                return Err(IdealVOLEError::new(
                    "delta mismatch between pregenerate and flush",
                ));
            }
        } else {
            self.delta = Some(flush_msg.delta);
        }

        let values: Vec<W> = self.pending_targets.drain(..flush_msg.count).collect();
        self.materialize(flush_msg.seed, flush_msg.offset, &values, flush_msg.delta);
        self.pending_alloc = 0;
        self.drain_queue();

        Ok(())
    }
}

impl<W, E> VOLEReceiver<W, E> for IdealVOLEReceiver<W, E>
where
    W: Field,
    E: ExtensionField<W>,
{
    type Error = IdealVOLEError;
    type Future = MaybeDone<VOLEReceiverOutput<E>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.pregenerated {
            return Ok(());
        }
        self.pending_alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.macs.len()
    }

    fn queue_recv_vole(&mut self, values: &[W]) -> Result<Self::Future, Self::Error> {
        let count = values.len();
        if self.pregenerated && count > self.macs.len() {
            return Err(IdealVOLEError::new(format!(
                "not enough pregenerated VOLEs: available={}, requested={}",
                self.macs.len(),
                count
            )));
        }
        // `pending_targets` is only read during the lazy flush path,
        // where it pairs with regenerated keys to compute MACs. In
        // pregenerated mode MACs are already materialized and this
        // buffer is never touched again — skip the copy.
        if !self.pregenerated {
            self.pending_targets.extend_from_slice(values);
        }
        let (send, recv) = new_output();
        if self.macs.len() >= count {
            // Same drain-whole-buffer trap as the sender: swap when
            // consuming everything.
            let macs: Vec<E> = if count == self.macs.len() {
                let _ = mem::take(&mut self.values);
                mem::take(&mut self.macs)
            } else {
                let _ = self.values.drain(..count).collect::<Vec<_>>();
                self.macs.drain(..count).collect()
            };
            send.send(VOLEReceiverOutput {
                id: self.vole_id.next(),
                macs,
            });
        } else {
            self.queue.push((count, send));
        }
        Ok(recv)
    }
}

/// Ideal VOLE error.
#[derive(Debug, thiserror::Error)]
#[error("ideal VOLE error: {0}")]
pub struct IdealVOLEError(String);

impl IdealVOLEError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::assert_vole;
    use mpz_common::future::Output;
    use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
    use rand::{Rng, SeedableRng};

    /// Test using separate sender/receiver with explicit message passing.
    #[test]
    fn test_ideal_vole_separate() {
        let mut rng = SmallRng::seed_from_u64(42);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();

        let (mut sender, mut receiver) = ideal_vole::<Gf2, Gf2_128>(seed, delta);

        const COUNT: usize = 128;
        let targets: Vec<Gf2> = (0..COUNT).map(|_| rng.random()).collect();

        sender.alloc(COUNT).unwrap();
        receiver.alloc(COUNT).unwrap();

        let mut send_fut = sender.queue_send_vole(COUNT).unwrap();
        let mut recv_fut = receiver.queue_recv_vole(&targets).unwrap();

        assert!(sender.wants_flush());
        assert!(receiver.wants_flush());

        assert!(matches!(send_fut.try_recv(), Ok(None)));
        assert!(matches!(recv_fut.try_recv(), Ok(None)));

        let msg = sender.flush().expect("should have message");
        receiver.flush(msg).unwrap();

        assert!(!sender.wants_flush());
        assert!(!receiver.wants_flush());

        let sender_out = send_fut.try_recv().unwrap().expect("resolved after flush");
        let receiver_out = recv_fut.try_recv().unwrap().expect("resolved after flush");

        assert_eq!(sender_out.id, receiver_out.id);
        assert_vole(delta, &sender_out.keys, &targets, &receiver_out.macs);
    }

    /// Test multiple `queue_recv_vole` calls in a single flush batch.
    #[test]
    fn test_ideal_vole_multiple_queues() {
        let mut rng = SmallRng::seed_from_u64(99);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();

        let (mut sender, mut receiver) = ideal_vole::<Gf2, Gf2_128>(seed, delta);

        let t1: Vec<Gf2> = (0..10).map(|_| rng.random()).collect();
        let t2: Vec<Gf2> = (0..15).map(|_| rng.random()).collect();
        let all_targets: Vec<Gf2> = t1.iter().chain(&t2).copied().collect();
        let count = all_targets.len();

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();
        let mut fut1 = receiver.queue_recv_vole(&t1).unwrap();
        let mut fut2 = receiver.queue_recv_vole(&t2).unwrap();
        let mut send_fut = sender.queue_send_vole(count).unwrap();

        let msg = sender.flush().unwrap();
        receiver.flush(msg).unwrap();

        let sender_out = send_fut.try_recv().unwrap().expect("resolved");
        let out1 = fut1.try_recv().unwrap().expect("resolved");
        let out2 = fut2.try_recv().unwrap().expect("resolved");

        let all_macs: Vec<Gf2_128> = out1.macs.iter().chain(&out2.macs).copied().collect();
        assert_vole(delta, &sender_out.keys, &all_targets, &all_macs);
    }

    /// Over-consuming is rejected.
    #[test]
    fn test_ideal_vole_over_consume_is_rejected() {
        let mut rng = SmallRng::seed_from_u64(0);
        let delta: Gf2_128 = rng.random();
        let (mut sender, _receiver) = ideal_vole::<Gf2, Gf2_128>(0, delta);
        sender.alloc(4).unwrap();
        let _ = sender.flush().unwrap();
        assert!(sender.try_send_vole(5).is_err());
    }
}
