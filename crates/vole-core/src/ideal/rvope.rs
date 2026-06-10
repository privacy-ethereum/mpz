//! Ideal Random VOPE functionality.
//!
//! This implementation uses message-based communication where the sender
//! produces a `FlushMsg` that the receiver consumes. Polynomial
//! coefficients are generated deterministically from a shared seed.

use std::mem;

use hybrid_array::Array;
use mpz_common::future::{MaybeDone, Sender, new_output};
use mpz_fields::Field;
use rand::{RngCore, SeedableRng, rngs::SmallRng};
use serde::{Deserialize, Serialize};

use crate::{
    VoleId,
    rvope::{RVOPEReceiver, RVOPEReceiverOutput, RVOPESender, RVOPESenderOutput},
};

/// Message sent from sender to receiver during flush.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushMsg<E: Field> {
    /// Base seed for polynomial generation.
    pub seed: u64,
    /// Offset into the correlation sequence.
    pub offset: u64,
    /// Number of RVOPEs to generate.
    pub count: usize,
    /// Degree of each polynomial.
    pub degree: usize,
    /// Global correlation delta.
    pub delta: E,
}

/// Generate polynomial coefficients deterministically from `(seed, offset)`.
fn generate_polynomials<E: Field>(
    seed: u64,
    offset: u64,
    count: usize,
    degree: usize,
) -> Vec<Vec<E>> {
    let mut rng = SmallRng::seed_from_u64(seed.wrapping_add(offset));
    (0..count)
        .map(|_| {
            (0..degree)
                .map(|_| {
                    let mut buf: Array<u8, E::ByteSize> = Array::default();
                    rng.fill_bytes(buf.as_mut_slice());
                    E::try_from(buf).expect("uniform bytes should yield a valid field element")
                })
                .collect()
        })
        .collect()
}

/// Evaluate polynomial `p` at `delta`.
fn eval_at<E: Field>(p: &[E], delta: E) -> E {
    let mut acc = E::zero();
    let mut power = E::one();
    for &c in p {
        acc = acc + c * power;
        power = power * delta;
    }
    acc
}

/// Returns a new ideal RVOPE sender and receiver.
pub fn ideal_rvope<E: Field>(seed: u64, delta: E) -> (IdealRVOPESender<E>, IdealRVOPEReceiver<E>) {
    (
        IdealRVOPESender::new(seed, delta),
        IdealRVOPEReceiver::new(seed),
    )
}

/// Pending allocation entry.
#[derive(Debug, Clone, Copy)]
struct Pending {
    count: usize,
    degree: usize,
}

/// Ideal RVOPE sender.
#[derive(Debug)]
pub struct IdealRVOPESender<E: Field> {
    seed: u64,
    delta: E,
    /// Current offset into correlation sequence.
    offset: u64,
    /// Pending allocation entries.
    pending: Vec<Pending>,
    /// Generated evaluations.
    evaluations: Vec<E>,
    /// Degrees parallel to `evaluations`.
    degrees: Vec<usize>,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<RVOPESenderOutput<E>>)>,
    /// VOPE ID counter.
    vope_id: VoleId,
    /// Sticky flag: once `pregenerate` has been called, `flush` stops
    /// generating. Under-sized pregeneration surfaces as an error on
    /// `try_send_vope` / `queue_send_vope`.
    pregenerated: bool,
}

impl<E: Field> IdealRVOPESender<E> {
    /// Creates a new sender with the given seed and delta.
    pub fn new(seed: u64, delta: E) -> Self {
        Self {
            seed,
            delta,
            offset: 0,
            pending: Vec::new(),
            evaluations: Vec::new(),
            degrees: Vec::new(),
            queue: Vec::new(),
            vope_id: VoleId::default(),
            pregenerated: false,
        }
    }

    /// Returns `true` if the sender wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        !self.pregenerated && (!self.pending.is_empty() || !self.queue.is_empty())
    }

    /// Pre-generates `count` RVOPE evaluations of the given `degree`
    /// immediately.
    ///
    /// Bypasses the alloc/flush cycle: polynomials are regenerated
    /// locally, evaluated at `delta`, and the evaluations pushed into
    /// the available pool. Intended for test/benchmark setup so the
    /// online consumption path does only bookkeeping.
    ///
    /// Once called, this sender is locked into pregenerated mode —
    /// `flush` becomes a no-op, and `try_send_vope` / `queue_send_vope`
    /// error with "not enough RVOPEs" if the pool runs dry.
    pub fn pregenerate(&mut self, count: usize, degree: usize) {
        self.pregenerated = true;
        // Absorb any prior lazy-mode alloc intent — it's dead state
        // once we've committed to pregenerated mode.
        self.pending.clear();
        self.materialize(count, degree);
        self.drain_queue();
    }

    /// Generates `count` polynomials of `degree` from the current
    /// `(seed, offset)`, evaluates each at `delta`, and advances
    /// `offset`.
    fn materialize(&mut self, count: usize, degree: usize) {
        let polys = generate_polynomials::<E>(self.seed, self.offset, count, degree);
        for p in &polys {
            self.evaluations.push(eval_at(p, self.delta));
            self.degrees.push(degree);
        }
        self.offset = self.offset.wrapping_add(count as u64);
    }

    /// Fulfills any queued `queue_send_vope` requests that the pool can
    /// now satisfy. Keeps `evaluations` and `degrees` in lockstep.
    fn drain_queue(&mut self) {
        for (queued_count, qsender) in mem::take(&mut self.queue) {
            if self.evaluations.len() >= queued_count {
                let len = self.evaluations.len();
                // Same stdlib `split_off(0)` trap as elsewhere — it
                // reallocates at the original's capacity.  Swap when
                // consuming everything.
                let evaluations = if queued_count == len {
                    self.degrees.clear();
                    mem::take(&mut self.evaluations)
                } else {
                    let out = self.evaluations.split_off(len - queued_count);
                    self.degrees.truncate(len - queued_count);
                    out
                };
                qsender.send(RVOPESenderOutput {
                    id: self.vope_id.next(),
                    evaluations,
                });
            }
        }
    }

    /// Flushes pending operations, returning one message per pending batch.
    ///
    /// Returns an empty Vec if the sender is in pregenerated mode
    /// (the pool is owned by `pregenerate` alone).
    pub fn flush(&mut self) -> Vec<FlushMsg<E>> {
        if self.pregenerated {
            return Vec::new();
        }
        let mut msgs = Vec::new();
        let pending = mem::take(&mut self.pending);

        for Pending { count, degree } in pending {
            let current_offset = self.offset;
            self.materialize(count, degree);
            msgs.push(FlushMsg {
                seed: self.seed,
                offset: current_offset,
                count,
                degree,
                delta: self.delta,
            });
        }

        self.drain_queue();

        msgs
    }
}

impl<E: Field> RVOPESender<E> for IdealRVOPESender<E> {
    type Error = IdealRVOPEError;
    type Future = MaybeDone<RVOPESenderOutput<E>>;

    fn alloc(&mut self, count: usize, degree: usize) -> Result<(), Self::Error> {
        if self.pregenerated {
            return Ok(());
        }
        self.pending.push(Pending { count, degree });
        Ok(())
    }

    fn available(&self) -> usize {
        self.evaluations.len()
    }

    fn try_send_vope(&mut self, count: usize) -> Result<RVOPESenderOutput<E>, Self::Error> {
        if count > self.evaluations.len() {
            return Err(IdealRVOPEError::new(format!(
                "not enough RVOPEs: available={}, requested={}",
                self.evaluations.len(),
                count
            )));
        }
        let len = self.evaluations.len();
        // stdlib's `split_off(0)` reallocates a fresh buffer at the
        // original's capacity — non-negligible when element count is in
        // the millions. Swap when consuming everything.
        let evaluations = if count == len {
            self.degrees.clear();
            mem::take(&mut self.evaluations)
        } else {
            let out = self.evaluations.split_off(len - count);
            self.degrees.truncate(len - count);
            out
        };
        Ok(RVOPESenderOutput {
            id: self.vope_id.next(),
            evaluations,
        })
    }

    fn queue_send_vope(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.pregenerated && count > self.evaluations.len() {
            return Err(IdealRVOPEError::new(format!(
                "not enough pregenerated RVOPEs: available={}, requested={}",
                self.evaluations.len(),
                count
            )));
        }
        let (send, recv) = new_output();
        if self.evaluations.len() >= count {
            let len = self.evaluations.len();
            // Same `split_off(0)` trap as `try_send_vope`; swap when
            // consuming everything.
            let evaluations = if count == len {
                self.degrees.clear();
                mem::take(&mut self.evaluations)
            } else {
                let out = self.evaluations.split_off(len - count);
                self.degrees.truncate(len - count);
                out
            };
            send.send(RVOPESenderOutput {
                id: self.vope_id.next(),
                evaluations,
            });
        } else {
            self.queue.push((count, send));
        }
        Ok(recv)
    }
}

/// Ideal RVOPE receiver.
#[derive(Debug)]
pub struct IdealRVOPEReceiver<E: Field> {
    /// Shared seed (same as sender's).
    seed: u64,
    /// Current offset into the correlation sequence.
    offset: u64,
    /// Pending allocation entries.
    pending: Vec<Pending>,
    /// Received polynomials.
    polynomials: Vec<Vec<E>>,
    /// Queue of (count, sender) for deferred output.
    queue: Vec<(usize, Sender<RVOPEReceiverOutput<E>>)>,
    /// VOPE ID counter.
    vope_id: VoleId,
    /// Sticky flag: once `pregenerate` has been called, `flush` stops
    /// generating. Under-sized pregeneration surfaces as an error on
    /// `try_recv_vope` / `queue_recv_vope`.
    pregenerated: bool,
    _marker: std::marker::PhantomData<E>,
}

impl<E: Field> IdealRVOPEReceiver<E> {
    /// Creates a new receiver with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            offset: 0,
            pending: Vec::new(),
            polynomials: Vec::new(),
            queue: Vec::new(),
            vope_id: VoleId::default(),
            pregenerated: false,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns `true` if the receiver wants to be flushed.
    pub fn wants_flush(&self) -> bool {
        !self.pregenerated && (!self.pending.is_empty() || !self.queue.is_empty())
    }

    /// Pre-generates `count` RVOPE polynomials of the given `degree`
    /// immediately.
    ///
    /// Bypasses the alloc/flush cycle: polynomials are materialized
    /// locally and pushed into the available pool. Intended for
    /// test/benchmark setup so the online consumption path does only
    /// bookkeeping.
    ///
    /// Once called, this receiver is locked into pregenerated mode —
    /// `flush` becomes a no-op, and `try_recv_vope` / `queue_recv_vope`
    /// error with "not enough RVOPEs" if the pool runs dry.
    pub fn pregenerate(&mut self, count: usize, degree: usize) {
        self.pregenerated = true;
        // Absorb any prior lazy-mode alloc intent — it's dead state
        // once we've committed to pregenerated mode.
        self.pending.clear();
        self.materialize(self.seed, self.offset, count, degree);
        self.offset = self.offset.wrapping_add(count as u64);
        self.drain_queue();
    }

    /// Generates `count` polynomials of `degree` from `(seed, offset)`
    /// and extends the pool. Does not advance `self.offset` — callers
    /// handle that depending on their seed/offset source.
    fn materialize(&mut self, seed: u64, offset: u64, count: usize, degree: usize) {
        let polys = generate_polynomials::<E>(seed, offset, count, degree);
        self.polynomials.extend(polys);
    }

    /// Fulfills any queued `queue_recv_vope` requests that the pool can
    /// now satisfy.
    fn drain_queue(&mut self) {
        for (queued_count, qsender) in mem::take(&mut self.queue) {
            if self.polynomials.len() >= queued_count {
                let len = self.polynomials.len();
                let polynomials = if queued_count == len {
                    mem::take(&mut self.polynomials)
                } else {
                    self.polynomials.split_off(len - queued_count)
                };
                qsender.send(RVOPEReceiverOutput {
                    id: self.vope_id.next(),
                    polynomials,
                });
            }
        }
    }

    /// Flushes one pending batch using the message from the sender.
    pub fn flush(&mut self, flush_msg: FlushMsg<E>) -> Result<(), IdealRVOPEError> {
        if self.pregenerated {
            return Ok(());
        }
        let Pending { count, degree } = self
            .pending
            .first()
            .copied()
            .ok_or_else(|| IdealRVOPEError::new("received flush with no pending alloc"))?;

        if flush_msg.count != count || flush_msg.degree != degree {
            return Err(IdealRVOPEError::new(format!(
                "flush mismatch: pending (count={count}, degree={degree}), got (count={}, degree={})",
                flush_msg.count, flush_msg.degree
            )));
        }
        self.pending.remove(0);

        self.materialize(
            flush_msg.seed,
            flush_msg.offset,
            flush_msg.count,
            flush_msg.degree,
        );
        self.drain_queue();

        Ok(())
    }
}

impl<E: Field> RVOPEReceiver<E> for IdealRVOPEReceiver<E> {
    type Error = IdealRVOPEError;
    type Future = MaybeDone<RVOPEReceiverOutput<E>>;

    fn alloc(&mut self, count: usize, degree: usize) -> Result<(), Self::Error> {
        if self.pregenerated {
            return Ok(());
        }
        self.pending.push(Pending { count, degree });
        Ok(())
    }

    fn available(&self) -> usize {
        self.polynomials.len()
    }

    fn try_recv_vope(&mut self, count: usize) -> Result<RVOPEReceiverOutput<E>, Self::Error> {
        if count > self.polynomials.len() {
            return Err(IdealRVOPEError::new(format!(
                "not enough RVOPEs: available={}, requested={}",
                self.polynomials.len(),
                count
            )));
        }
        let len = self.polynomials.len();
        // stdlib's `split_off(0)` reallocates a fresh buffer at the
        // original's capacity — non-negligible when element count is in
        // the millions. Swap when consuming everything.
        let polynomials = if count == len {
            mem::take(&mut self.polynomials)
        } else {
            self.polynomials.split_off(len - count)
        };
        Ok(RVOPEReceiverOutput {
            id: self.vope_id.next(),
            polynomials,
        })
    }

    fn queue_recv_vope(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        if self.pregenerated && count > self.polynomials.len() {
            return Err(IdealRVOPEError::new(format!(
                "not enough pregenerated RVOPEs: available={}, requested={}",
                self.polynomials.len(),
                count
            )));
        }
        let (send, recv) = new_output();
        if self.polynomials.len() >= count {
            let len = self.polynomials.len();
            // Same trap as `try_recv_vope`; swap when consuming everything.
            let polynomials = if count == len {
                mem::take(&mut self.polynomials)
            } else {
                self.polynomials.split_off(len - count)
            };
            send.send(RVOPEReceiverOutput {
                id: self.vope_id.next(),
                polynomials,
            });
        } else {
            self.queue.push((count, send));
        }
        Ok(recv)
    }
}

/// Ideal RVOPE error.
#[derive(Debug, thiserror::Error)]
#[error("ideal RVOPE error: {0}")]
pub struct IdealRVOPEError(String);

impl IdealRVOPEError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::assert_vope;
    use mpz_fields::gf2_128::Gf2_128;
    use rand::Rng;

    /// Test using separate sender/receiver with explicit message passing.
    #[test]
    fn test_ideal_rvope_separate() {
        let mut rng = SmallRng::seed_from_u64(42);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();

        let (mut sender, mut receiver) = ideal_rvope::<Gf2_128>(seed, delta);

        const COUNT: usize = 4;
        const DEGREE: usize = 8;

        sender.alloc(COUNT, DEGREE).unwrap();
        receiver.alloc(COUNT, DEGREE).unwrap();

        assert!(sender.wants_flush());
        assert!(receiver.wants_flush());

        let msgs = sender.flush();
        assert_eq!(msgs.len(), 1);
        for msg in msgs {
            receiver.flush(msg).unwrap();
        }

        assert!(!sender.wants_flush());
        assert!(!receiver.wants_flush());
        assert_eq!(sender.available(), COUNT);
        assert_eq!(receiver.available(), COUNT);

        let sender_out = sender.try_send_vope(COUNT).unwrap();
        let receiver_out = receiver.try_recv_vope(COUNT).unwrap();

        assert_eq!(sender_out.id, receiver_out.id);
        for poly in &receiver_out.polynomials {
            assert_eq!(poly.len(), DEGREE);
        }
        assert_vope(delta, &receiver_out.polynomials, &sender_out.evaluations);
    }

    /// Test multiple alloc batches with different degrees.
    #[test]
    fn test_ideal_rvope_mixed_degrees() {
        let mut rng = SmallRng::seed_from_u64(99);
        let seed: u64 = rng.random();
        let delta: Gf2_128 = rng.random();

        let (mut sender, mut receiver) = ideal_rvope::<Gf2_128>(seed, delta);

        sender.alloc(2, 4).unwrap();
        sender.alloc(3, 8).unwrap();
        receiver.alloc(2, 4).unwrap();
        receiver.alloc(3, 8).unwrap();

        let msgs = sender.flush();
        assert_eq!(msgs.len(), 2);
        for msg in msgs {
            receiver.flush(msg).unwrap();
        }

        let sender_out = sender.try_send_vope(5).unwrap();
        let receiver_out = receiver.try_recv_vope(5).unwrap();

        assert_vope(delta, &receiver_out.polynomials, &sender_out.evaluations);
    }

    /// Over-consuming is rejected.
    #[test]
    fn test_ideal_rvope_over_consume_is_rejected() {
        let mut rng = SmallRng::seed_from_u64(0);
        let delta: Gf2_128 = rng.random();
        let (mut sender, mut receiver) = ideal_rvope::<Gf2_128>(0, delta);
        sender.alloc(2, 4).unwrap();
        receiver.alloc(2, 4).unwrap();
        for msg in sender.flush() {
            receiver.flush(msg).unwrap();
        }

        assert!(sender.try_send_vope(3).is_err());
        assert!(receiver.try_recv_vope(3).is_err());
    }
}
