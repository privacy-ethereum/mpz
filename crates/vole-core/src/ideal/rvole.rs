//! Ideal Random VOLE functionality.
//!
//! This implementation uses message-based communication where the sender
//! produces a `FlushMsg` that the receiver consumes. Keys are generated
//! deterministically from a shared seed.

use std::mem;

use hybrid_array::Array;
use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_fields::{ExtensionField, Field};
use rand::{
    Rng, RngCore, SeedableRng,
    distr::{Distribution, StandardUniform},
    rngs::SmallRng,
};
use serde::{Deserialize, Serialize};

use crate::{
    VoleId,
    rvole::{RVOLEReceiver, RVOLEReceiverOutput, RVOLESender, RVOLESenderOutput},
};

/// Offset applied to the receiver's value-RNG seed so the value stream is
/// distinct from the key stream.
const RECEIVER_VALUE_SEED_OFFSET: u64 = 0xDEADBEEFCAFEBABE;

/// Message sent from sender to receiver during flush.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushMsg<E: Field> {
    /// Base seed for key generation.
    pub seed: u64,
    /// Offset into the key sequence.
    pub offset: u64,
    /// Number of RVOLEs to generate.
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

/// Returns a new ideal RVOLE sender and receiver.
pub fn ideal_rvole<W, E>(seed: u64, delta: E) -> (IdealRVOLESender<E>, IdealRVOLEReceiver<W, E>)
where
    W: Field,
    E: ExtensionField<W>,
    StandardUniform: Distribution<W>,
{
    (
        IdealRVOLESender::new(seed, delta),
        IdealRVOLEReceiver::new(seed),
    )
}

/// Ideal RVOLE sender.
#[derive(Debug)]
pub struct IdealRVOLESender<E: Field> {
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
    /// generating and the pool can only grow via further `pregenerate`
    /// calls. Under-sized pregeneration surfaces as an error on
    /// `try_send_vole` / `queue_send_vole`.
    pregenerated: bool,
}

impl<E: Field> IdealRVOLESender<E> {
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

    /// Pre-generates `count` RVOLEs immediately.
    ///
    /// Bypasses the alloc/flush cycle: keys are materialized locally and
    /// pushed into the available pool. Intended for test/benchmark setup
    /// so the online consumption path does only bookkeeping.
    ///
    /// Once called, this sender is locked into pregenerated mode —
    /// `flush` becomes a no-op, and `try_send_vole` / `queue_send_vole`
    /// error with "not enough RVOLEs" if the pool runs dry.
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
                let len = self.keys.len();
                let keys = self.keys.split_off(len - queued_count);
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

impl<E: Field> RVOLESender<E> for IdealRVOLESender<E> {
    type Error = IdealRVOLEError;
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
            return Err(IdealRVOLEError::new(format!(
                "not enough RVOLEs: available={}, requested={}",
                self.keys.len(),
                count
            )));
        }
        let len = self.keys.len();
        // stdlib's `split_off(0)` reallocates a fresh buffer with the
        // original's capacity — non-negligible when element count is in
        // the millions. When consuming everything, swap the vec out
        // for free instead.
        let keys = if count == len {
            mem::take(&mut self.keys)
        } else {
            self.keys.split_off(len - count)
        };
        Ok(RVOLESenderOutput {
            id: self.vole_id.next(),
            keys,
        })
    }

    fn queue_send_vole(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.pregenerated && count > self.keys.len() {
            return Err(IdealRVOLEError::new(format!(
                "not enough pregenerated RVOLEs: available={}, requested={}",
                self.keys.len(),
                count
            )));
        }
        let (send, recv) = new_output();
        if self.keys.len() >= count {
            let len = self.keys.len();
            let keys = self.keys.split_off(len - count);
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

/// Ideal RVOLE receiver.
#[derive(Debug)]
pub struct IdealRVOLEReceiver<W, E: Field> {
    /// Shared seed (same as sender's).
    seed: u64,
    /// Current offset into the key sequence.
    offset: u64,
    /// Cached delta, learned at the first `pregenerate` or `flush` call.
    delta: Option<E>,
    /// RNG for generating values (seeded for determinism).
    value_rng: SmallRng,
    /// Pending allocation count.
    pending: usize,
    /// Received values.
    values: Vec<W>,
    /// Received MACs.
    macs: Vec<E>,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<RVOLEReceiverOutput<W, E>>)>,
    /// VOLE ID counter.
    vole_id: VoleId,
    /// Sticky flag: once `pregenerate` has been called, `flush` stops
    /// generating. Under-sized pregeneration surfaces as an error on
    /// `try_recv_vole` / `queue_recv_vole`.
    pregenerated: bool,
}

impl<W, E> IdealRVOLEReceiver<W, E>
where
    W: Field,
    E: ExtensionField<W>,
    StandardUniform: Distribution<W>,
{
    /// Creates a new receiver with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            offset: 0,
            delta: None,
            value_rng: SmallRng::seed_from_u64(
                seed.wrapping_add(RECEIVER_VALUE_SEED_OFFSET),
            ),
            pending: 0,
            values: Vec::new(),
            macs: Vec::new(),
            queue: Vec::new(),
            vole_id: VoleId::default(),
            pregenerated: false,
        }
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        !self.pregenerated && (self.pending > 0 || !self.queue.is_empty())
    }

    /// Pre-generates `count` RVOLEs immediately, using `delta`.
    ///
    /// The first call sets the cached delta; subsequent calls (and later
    /// flushes) must match it. Intended for test/benchmark setup so the
    /// online consumption path does only bookkeeping.
    ///
    /// Once called, this receiver is locked into pregenerated mode —
    /// `flush` becomes a no-op, and `try_recv_vole` / `queue_recv_vole`
    /// error with "not enough RVOLEs" if the pool runs dry.
    pub fn pregenerate(&mut self, count: usize, delta: E) -> Result<(), IdealRVOLEError> {
        self.pregenerated = true;
        // Absorb any prior lazy-mode alloc intent — it's dead state
        // once we've committed to pregenerated mode.
        self.pending = 0;
        match self.delta {
            Some(existing) if existing != delta => {
                return Err(IdealRVOLEError::new("delta mismatch in pregenerate"));
            }
            _ => self.delta = Some(delta),
        }

        self.materialize(self.seed, self.offset, count, delta);
        self.offset = self.offset.wrapping_add(count as u64);
        self.drain_queue();

        Ok(())
    }

    /// Generates `count` keys from `(seed, offset)`, samples values
    /// from the receiver's RNG, computes MACs against `delta`, and
    /// extends both pools. Does not advance `self.offset` — callers
    /// handle that depending on their seed/offset source.
    fn materialize(&mut self, seed: u64, offset: u64, count: usize, delta: E) {
        let keys = generate_keys::<E>(seed, offset, count);
        let values: Vec<W> = (0..count).map(|_| self.value_rng.random::<W>()).collect();
        let macs: Vec<E> = keys
            .iter()
            .zip(&values)
            .map(|(k, v)| *k + delta * E::embed(*v))
            .collect();
        self.values.extend(values);
        self.macs.extend(macs);
    }

    /// Fulfills any queued `queue_recv_vole` requests that the pool can
    /// now satisfy.
    fn drain_queue(&mut self) {
        for (queued_count, qsender) in mem::take(&mut self.queue) {
            if self.values.len() >= queued_count {
                let len = self.values.len();
                let values = self.values.split_off(len - queued_count);
                let macs = self.macs.split_off(len - queued_count);
                qsender.send(RVOLEReceiverOutput {
                    id: self.vole_id.next(),
                    values,
                    macs,
                });
            }
        }
    }

    /// Flushes pending operations using the message from the sender.
    pub fn flush(&mut self, flush_msg: FlushMsg<E>) -> Result<(), IdealRVOLEError> {
        if self.pregenerated {
            return Ok(());
        }
        if flush_msg.count != self.pending {
            return Err(IdealRVOLEError::new(format!(
                "count mismatch: expected={}, received={}",
                self.pending, flush_msg.count
            )));
        }
        if let Some(existing) = self.delta {
            if existing != flush_msg.delta {
                return Err(IdealRVOLEError::new(
                    "delta mismatch between pregenerate and flush",
                ));
            }
        } else {
            self.delta = Some(flush_msg.delta);
        }

        self.materialize(
            flush_msg.seed,
            flush_msg.offset,
            flush_msg.count,
            flush_msg.delta,
        );
        self.pending = 0;
        self.drain_queue();

        Ok(())
    }
}

impl<W, E> RVOLEReceiver<W, E> for IdealRVOLEReceiver<W, E>
where
    W: Field,
    E: ExtensionField<W>,
    StandardUniform: Distribution<W>,
{
    type Error = IdealRVOLEError;
    type Future = MaybeDone<RVOLEReceiverOutput<W, E>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        if self.pregenerated {
            return Ok(());
        }
        self.pending += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.values.len()
    }

    fn try_recv_vole(
        &mut self,
        count: usize,
    ) -> Result<RVOLEReceiverOutput<W, E>, Self::Error> {
        if count > self.values.len() {
            return Err(IdealRVOLEError::new(format!(
                "not enough RVOLEs: available={}, requested={}",
                self.values.len(),
                count
            )));
        }
        let len = self.values.len();
        // Same stdlib trap as `try_send_vole`: `split_off(0)`
        // reallocates at the original's capacity. Swap instead when
        // consuming everything.
        let (values, macs) = if count == len {
            (mem::take(&mut self.values), mem::take(&mut self.macs))
        } else {
            (
                self.values.split_off(len - count),
                self.macs.split_off(len - count),
            )
        };
        Ok(RVOLEReceiverOutput {
            id: self.vole_id.next(),
            values,
            macs,
        })
    }

    fn queue_recv_vole(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.pregenerated && count > self.values.len() {
            return Err(IdealRVOLEError::new(format!(
                "not enough pregenerated RVOLEs: available={}, requested={}",
                self.values.len(),
                count
            )));
        }
        let (send, recv) = new_output();
        if self.values.len() >= count {
            let len = self.values.len();
            let values = self.values.split_off(len - count);
            let macs = self.macs.split_off(len - count);
            send.send(RVOLEReceiverOutput {
                id: self.vole_id.next(),
                values,
                macs,
            });
        } else {
            self.queue.push((count, send));
        }
        Ok(recv)
    }
}

/// Ideal RVOLE error.
#[derive(Debug, thiserror::Error)]
#[error("ideal RVOLE error: {0}")]
pub struct IdealRVOLEError(String);

impl IdealRVOLEError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::assert_vole;
    use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};

    /// Test using separate sender/receiver with explicit message passing.
    #[test]
    fn test_ideal_rvole_separate() {
        let mut rng = SmallRng::seed_from_u64(42);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();

        let (mut sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);

        const COUNT: usize = 128;

        sender.alloc(COUNT).unwrap();
        receiver.alloc(COUNT).unwrap();

        assert!(sender.wants_flush());
        assert!(receiver.wants_flush());

        let flush_msg = sender.flush().expect("should have message");
        receiver.flush(flush_msg).unwrap();

        assert!(!sender.wants_flush());
        assert!(!receiver.wants_flush());
        assert_eq!(sender.available(), COUNT);
        assert_eq!(receiver.available(), COUNT);

        let sender_out = sender.try_send_vole(COUNT).unwrap();
        let receiver_out = receiver.try_recv_vole(COUNT).unwrap();

        assert_eq!(sender_out.id, receiver_out.id);
        assert_vole(
            delta,
            &sender_out.keys,
            &receiver_out.values,
            &receiver_out.macs,
        );
    }

    /// Test the `queue_*_vole` path resolves after flush.
    #[test]
    fn test_ideal_rvole_queue() {
        use mpz_common::future::Output;

        let mut rng = SmallRng::seed_from_u64(7);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();

        let (mut sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(seed, delta);

        const COUNT: usize = 64;

        sender.alloc(COUNT).unwrap();
        receiver.alloc(COUNT).unwrap();

        let mut sender_fut = sender.queue_send_vole(COUNT).unwrap();
        let mut receiver_fut = receiver.queue_recv_vole(COUNT).unwrap();

        assert!(matches!(sender_fut.try_recv(), Ok(None)));
        assert!(matches!(receiver_fut.try_recv(), Ok(None)));

        let msg = sender.flush().expect("should have message");
        receiver.flush(msg).unwrap();

        let sender_out = sender_fut.try_recv().unwrap().expect("resolved after flush");
        let receiver_out = receiver_fut
            .try_recv()
            .unwrap()
            .expect("resolved after flush");

        assert_vole(
            delta,
            &sender_out.keys,
            &receiver_out.values,
            &receiver_out.macs,
        );
    }

    /// Over-consuming is rejected.
    #[test]
    fn test_ideal_rvole_over_consume_is_rejected() {
        let mut rng = SmallRng::seed_from_u64(0);
        let delta: Gf2_128 = rng.random();
        let (mut sender, mut receiver) = ideal_rvole::<Gf2, Gf2_128>(0, delta);
        sender.alloc(4).unwrap();
        receiver.alloc(4).unwrap();
        let msg = sender.flush().unwrap();
        receiver.flush(msg).unwrap();

        assert!(sender.try_send_vole(5).is_err());
        assert!(receiver.try_recv_vole(5).is_err());
    }
}
