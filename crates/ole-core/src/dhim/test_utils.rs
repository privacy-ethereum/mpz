//! Ideal / in-memory ROT sources.

use mpz_core::{Block, prg::Prg};
use mpz_ot_core::{
    ideal::rot::{IdealROTReceiver, IdealROTSender, ideal_rot},
    rot::{ROTReceiver, ROTSender},
};
use rand::RngCore;

use crate::dhim::{
    config::Config,
    rot::{RotReceiverShare, RotReceiverSource, RotSenderShare, RotSenderSource},
};

/// Total ROT correlations one OLE over `basis` consumes.
pub fn rots_per_ole(config: &Config) -> usize {
    config
        .crt
        .primes()
        .iter()
        .map(|&p| (u64::BITS - (p - 1).leading_zeros()) as usize)
        .sum()
}

/// Draws one correlation `(a₀, a₁, choice)` deterministically from `prg`.
///
/// Both party views are derived from the *same* draw, so any two streams seeded
/// identically and advanced in lockstep stay consistent.
fn draw(prg: &mut Prg, p: u64) -> (u64, u64, bool) {
    let a0 = draw_zp(prg, p);
    let a1 = draw_zp(prg, p);
    let choice = (draw_byte(prg) & 1) == 1;
    (a0, a1, choice)
}

fn draw_zp(prg: &mut Prg, p: u64) -> u64 {
    let mut b = [0u8; 8];
    prg.fill_bytes(&mut b);
    // Negligible modulo bias for p ≤ 1063 ≪ 2⁶⁴; ample for an ideal source.
    u64::from_le_bytes(b) % p
}

fn draw_byte(prg: &mut Prg) -> u8 {
    let mut b = [0u8; 1];
    prg.fill_bytes(&mut b);
    b[0]
}

/// In-memory ideal ROT source (Functionality 3.11) for tests and local
/// simulation. Returns the **paired** sender and receiver views together, so
/// consistency is guaranteed by construction.
pub struct IdealRot {
    prg: Prg,
}

impl IdealRot {
    /// Creates an ideal source seeded by `seed`.
    pub fn new(seed: [u8; 16]) -> Self {
        Self {
            prg: Prg::new_with_seed(seed),
        }
    }

    /// Draws the next ROT correlation over `Z_p`, returning `(sender,
    /// receiver)` views that satisfy `receiver.msg = if receiver.choice {
    /// sender.a1 } else { sender.a0 }`.
    pub fn next(&mut self, p: u64) -> (RotSenderShare, RotReceiverShare) {
        let (a0, a1, choice) = draw(&mut self.prg, p);
        let msg = if choice { a1 } else { a0 };
        (RotSenderShare { a0, a1 }, RotReceiverShare { choice, msg })
    }
}

/// Ideal ROT **sender** stream (one party's view of a shared correlation pool).
pub struct IdealRotSender {
    prg: Prg,
}

/// Ideal ROT **receiver** stream (one party's view of a shared correlation
/// pool).
pub struct IdealRotReceiver {
    prg: Prg,
}

/// Creates a consistent ideal sender/receiver pair from a shared `seed`.
///
/// Both streams derive identical correlations as long as they are advanced in
/// lockstep (same sequence of `next_*` calls with the same primes) — which the
/// upper-layer protocols do by construction.
pub fn ideal_rot_pair(seed: [u8; 16]) -> (IdealRotSender, IdealRotReceiver) {
    (
        IdealRotSender {
            prg: Prg::new_with_seed(seed),
        },
        IdealRotReceiver {
            prg: Prg::new_with_seed(seed),
        },
    )
}

impl RotSenderSource for IdealRotSender {
    // PRG-backed infinite stream: correlations are drawn on demand, so there is
    // nothing to pre-allocate.
    fn alloc(&mut self, _count: usize) {}

    fn next_sender(&mut self, p: u64) -> RotSenderShare {
        let (a0, a1, _choice) = draw(&mut self.prg, p);
        RotSenderShare { a0, a1 }
    }
}

impl RotReceiverSource for IdealRotReceiver {
    // PRG-backed infinite stream: nothing to pre-allocate.
    fn alloc(&mut self, _count: usize) {}

    fn next_receiver(&mut self, p: u64) -> RotReceiverShare {
        let (a0, a1, choice) = draw(&mut self.prg, p);
        let msg = if choice { a1 } else { a0 };
        RotReceiverShare { choice, msg }
    }
}

/// Builds a **pre-flushed** ideal ROT pair with `count` correlations ready to
/// consume, for tests and benchmarks.
pub fn preflushed_ideal_rot(seed: [u8; 16], count: usize) -> (IdealROTSender, IdealROTReceiver) {
    let (mut sender, mut receiver) = ideal_rot(Block::from(seed));
    sender.alloc(count).expect("alloc sender");
    receiver.alloc(count).expect("alloc receiver");
    let flush = sender.flush().expect("sender has pending correlations");
    receiver.flush(flush).expect("receiver flush matches");
    (sender, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::rot::{RotReceiverSource, RotSenderSource};

    #[test]
    fn paired_shares_are_consistent() {
        let mut pool = IdealRot::new([1u8; 16]);
        for &p in &[5u64, 97, 1063] {
            for _ in 0..200 {
                let (s, r) = pool.next(p);
                assert!(s.a0 < p && s.a1 < p);
                assert_eq!(r.msg, if r.choice { s.a1 } else { s.a0 });
            }
        }
    }

    #[test]
    fn split_streams_stay_in_lockstep() {
        let (mut send, mut recv) = ideal_rot_pair([42u8; 16]);
        for &p in &[7u64, 101, 1009] {
            for _ in 0..200 {
                let s = send.next_sender(p);
                let r = recv.next_receiver(p);
                assert!(s.a0 < p && s.a1 < p);
                assert_eq!(r.msg, if r.choice { s.a1 } else { s.a0 });
            }
        }
    }

    #[test]
    fn choice_bit_is_not_constant() {
        let (mut send, mut recv) = ideal_rot_pair([7u8; 16]);
        let mut zeros = 0;
        let mut ones = 0;
        for _ in 0..500 {
            let _ = send.next_sender(1063);
            if recv.next_receiver(1063).choice {
                ones += 1;
            } else {
                zeros += 1;
            }
        }
        assert!(
            zeros > 50 && ones > 50,
            "choice bit looks degenerate: {zeros}/{ones}"
        );
    }
}
