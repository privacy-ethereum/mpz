//! Random OT correlations over `Z_p` (Functionality 3.11).

use std::collections::VecDeque;

use crypto_bigint::{Limb, NonZero, Reciprocal, U128};
use mpz_core::Block;
use mpz_ot_core::rot::{ROTReceiver, ROTSender};

/// One ROT correlation over `Z_p`, the **sender's** view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotSenderShare {
    /// Message for choice bit `0`.
    pub a0: u64,
    /// Message for choice bit `1`.
    pub a1: u64,
}

/// One ROT correlation over `Z_p`, the **receiver's** view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotReceiverShare {
    /// The (random) choice bit `i`.
    pub choice: bool,
    /// The selected message `a_i`.
    pub msg: u64,
}

/// A source of ROT **sender**-shares over `Z_p`, supplied externally.
pub trait RotSenderSource {
    /// Allocates `count` ROT correlations.
    fn alloc(&mut self, count: usize);

    /// Consumes and returns the next sender-share for a ROT over `Z_p`.
    fn next_sender(&mut self, p: u64) -> RotSenderShare;
}

/// A source of ROT **receiver**-shares over `Z_p`, supplied externally.
pub trait RotReceiverSource {
    /// Allocates `count` ROT correlations.
    fn alloc(&mut self, count: usize);

    /// Consumes and returns the next receiver-share for a ROT over `Z_p`.
    fn next_receiver(&mut self, p: u64) -> RotReceiverShare;
}

/// Exclusive upper bound on prime values indexed into [`BARRETT_RECIPROCALS`].
/// Must exceed the largest CRT prime any config uses (P-256's largest is 1049).
const BARRETT_MAX: usize = 1056;

/// Barrett reciprocals for every divisor `v ∈ [1, BARRETT_MAX)`, indexed by
/// value.
static BARRETT_RECIPROCALS: [Reciprocal; BARRETT_MAX] = {
    let mut t = [Reciprocal::default(); BARRETT_MAX];
    let mut v = 1usize;
    while v < BARRETT_MAX {
        t[v] = Reciprocal::new(NonZero::<Limb>::new_unwrap(Limb::from_u64(v as u64)));
        v += 1;
    }
    t
};

/// Reduces a 128-bit ROT message into `Z_p`. Assumes `p < BARRETT_MAX`.
fn block_mod_p(b: Block, p: u64) -> u64 {
    U128::from_le_slice(&b.to_bytes())
        .rem_limb_with_reciprocal(&BARRETT_RECIPROCALS[p as usize])
        .0
}

/// Sender-side adapter that turns wide (128-bit) random-OT correlations into
/// the small per-prime `Z_p` shares the protocol consumes.
pub struct BlockToZpSender<S> {
    /// The wrapped provider of wide (128-bit) ROT sender-correlations.
    inner: S,
    /// Correlations pulled from `inner` but not yet dispensed: refilled in one
    /// drain when empty, popped one per `next_sender`.
    buf: VecDeque<[Block; 2]>,
}

impl<S: ROTSender<[Block; 2]>> BlockToZpSender<S> {
    /// Wraps an mpz ROT sender provider.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buf: VecDeque::new(),
        }
    }
}

impl<S: ROTSender<[Block; 2]>> RotSenderSource for BlockToZpSender<S> {
    fn alloc(&mut self, count: usize) {
        self.inner.alloc(count).expect("ROT sender alloc");
    }

    fn next_sender(&mut self, p: u64) -> RotSenderShare {
        if self.buf.is_empty() {
            // The pool is pre-flushed all-or-nothing, so drain everything the
            // provider has in one pull; exhaustion is the only failure mode.
            let n = self.inner.available();
            assert!(n > 0, "ROT provider exhausted: pre-flush more correlations");
            let out = self
                .inner
                .try_send_rot(n)
                .expect("try_send_rot from a filled pool");
            self.buf.extend(out.keys);
        }
        let [k0, k1] = self.buf.pop_front().expect("buffer refilled above");
        RotSenderShare {
            a0: block_mod_p(k0, p),
            a1: block_mod_p(k1, p),
        }
    }
}

/// Receiver-side adapter that turns wide (128-bit) random-OT correlations into
/// the small per-prime `Z_p` shares the protocol consumes.
pub struct BlockToZpReceiver<R> {
    /// The wrapped provider of wide (128-bit) ROT receiver-correlations.
    inner: R,
    /// `(choice, msg)` pairs pulled from `inner` but not yet dispensed:
    /// refilled in one drain when empty, popped one per `next_receiver`.
    buf: VecDeque<(bool, Block)>,
}

impl<R: ROTReceiver<bool, Block>> BlockToZpReceiver<R> {
    /// Wraps an mpz ROT receiver provider.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: VecDeque::new(),
        }
    }
}

impl<R: ROTReceiver<bool, Block>> RotReceiverSource for BlockToZpReceiver<R> {
    fn alloc(&mut self, count: usize) {
        self.inner.alloc(count).expect("ROT receiver alloc");
    }

    fn next_receiver(&mut self, p: u64) -> RotReceiverShare {
        if self.buf.is_empty() {
            // The pool is pre-flushed all-or-nothing, so drain everything the
            // provider has in one pull; exhaustion is the only failure mode.
            let n = self.inner.available();
            assert!(n > 0, "ROT provider exhausted: pre-flush more correlations");
            let out = self
                .inner
                .try_recv_rot(n)
                .expect("try_recv_rot from a filled pool");
            self.buf.extend(out.choices.into_iter().zip(out.msgs));
        }
        let (choice, msg) = self.buf.pop_front().expect("buffer refilled above");
        RotReceiverShare {
            choice,
            msg: block_mod_p(msg, p),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::{config::p256::P256_PRIMES, test_utils::preflushed_ideal_rot};

    /// `block_mod_p` agrees with a direct `u128 % p` over boundary values and
    /// the extreme CRT primes — pinning the Barrett-reciprocal reduction
    /// path (including the little-endian interpretation of the block
    /// bytes).
    #[test]
    fn block_mod_p_matches_reference() {
        let values: [u128; 7] = [
            0,
            1,
            u128::MAX,
            1u128 << 64,
            0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
            12_345_678_901_234_567_890,
            (1u128 << 127) | 1,
        ];
        // Smallest, a mid-range, and the largest P-256 prime.
        for &p in &[5u64, 257, 1049] {
            for &v in &values {
                let b = Block::from(v.to_le_bytes());
                assert_eq!(block_mod_p(b, p), (v % p as u128) as u64, "v={v}, p={p}");

                // An exact multiple of p reduces to 0.
                let mult = (v / p as u128) * p as u128;
                assert_eq!(block_mod_p(Block::from(mult.to_le_bytes()), p), 0, "p={p}");
            }
        }
    }

    /// The Barrett table is large enough for every production CRT prime, so
    /// `block_mod_p`'s `BARRETT_RECIPROCALS[p]` can never index out of bounds.
    /// Promotes the comment on `BARRETT_MAX` to a checked invariant.
    #[test]
    fn barrett_table_covers_all_primes() {
        let max_prime = *P256_PRIMES.iter().max().expect("non-empty prime set");
        assert!(
            (max_prime as usize) < BARRETT_MAX,
            "largest CRT prime {max_prime} must be < BARRETT_MAX {BARRETT_MAX}"
        );
    }

    /// The core ROT-over-`Z_p` guarantee, end-to-end through both adapters: the
    /// receiver's reduced message equals the sender's message at the receiver's
    /// choice bit, and every value lands in `[0, p)`. Also exercises the
    /// drain-all-then-pop buffer path (one pull feeds all `COUNT` draws).
    #[test]
    fn adapters_preserve_rot_correlation() {
        const COUNT: usize = 64;
        for (seed, &p) in [5u64, 257, 1049].iter().enumerate() {
            let (s_inner, r_inner) = preflushed_ideal_rot([seed as u8; 16], COUNT);
            let mut sender = BlockToZpSender::new(s_inner);
            let mut receiver = BlockToZpReceiver::new(r_inner);

            for i in 0..COUNT {
                let s = sender.next_sender(p);
                let r = receiver.next_receiver(p);

                assert!(s.a0 < p && s.a1 < p, "sender shares < p (i={i}, p={p})");
                assert!(r.msg < p, "receiver msg < p (i={i}, p={p})");

                let expected = if r.choice { s.a1 } else { s.a0 };
                assert_eq!(r.msg, expected, "ROT selection wrong (i={i}, p={p})");
            }
        }
    }
}
