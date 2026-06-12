//! Correlated OT over `Z_p` from random OT (Protocol 3.15).

use crate::dhim::rot::{RotReceiverShare, RotSenderShare};

use super::zp;

/// The sender → receiver correction message `o` of Protocol 3.15.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Correction {
    /// `o = a₁ − a₀ − δ mod p` (after the conditional swap).
    pub(crate) o: u64,
}

/// **Receiver, step 1.** Returns the bit `f = choice ⊕ i` to send to the
/// sender, where `i = rot.choice` is the ROT's random selection.
pub(crate) fn receiver_flip(rot: &RotReceiverShare, choice: bool) -> bool {
    choice ^ rot.choice
}

/// **Sender, step 2.** Consumes the ROT sender-share and the offset `δ`,
/// applies the conditional swap dictated by `f`, and returns:
///
/// * the sender's `COT_p` output `a₀` (the random pad), and
/// * the [`Correction`] `o` to send to the receiver.
///
/// Requires `delta < p` (and the ROT messages reduced mod `p`).
pub(crate) fn sender_step(rot: RotSenderShare, delta: u64, f: bool, p: u64) -> (u64, Correction) {
    debug_assert!(delta < p && rot.a0 < p && rot.a1 < p);
    let (a0, a1) = if f {
        (rot.a1, rot.a0)
    } else {
        (rot.a0, rot.a1)
    };
    // o = a₁ − a₀ − δ  (mod p)
    let o = zp::sub(zp::sub(a1, a0, p), delta, p);
    (a0, Correction { o })
}

/// **Receiver, step 3.** Consumes the ROT receiver-share, its real `choice`,
/// and the sender's [`Correction`], and returns the `COT_p` output
/// `a₀ + choice·δ`.
pub(crate) fn receiver_output(
    rot: RotReceiverShare,
    choice: bool,
    corr: Correction,
    p: u64,
) -> u64 {
    debug_assert!(rot.msg < p && corr.o < p);
    if choice {
        zp::sub(rot.msg, corr.o, p)
    } else {
        rot.msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::test_utils::IdealRot;

    /// End-to-end Protocol 3.15: drive one COT from one ideal ROT and check the
    /// `COT_p` relation `receiver_out = sender_a₀ + choice·δ`.
    fn run_one(pool: &mut IdealRot, p: u64, delta: u64, choice: bool) -> (u64, u64) {
        let (s_share, r_share) = pool.next(p);
        let f = receiver_flip(&r_share, choice);
        let (sender_a0, corr) = sender_step(s_share, delta, f, p);
        let receiver_out = receiver_output(r_share, choice, corr, p);
        (sender_a0, receiver_out)
    }

    #[test]
    fn cot_relation_holds() {
        let mut pool = IdealRot::new([9u8; 16]);
        // Deterministic spread of (delta, choice) over several primes.
        for &p in &[5u64, 7, 13, 97, 1009, 1063] {
            for k in 0..(2 * p) {
                let delta = k % p;
                let choice = (k / p) % 2 == 1;
                let (a0, out) = run_one(&mut pool, p, delta, choice);
                let expected = (a0 + (choice as u64 * delta) % p) % p;
                assert_eq!(out, expected, "p={p} delta={delta} choice={choice}");
            }
        }
    }

    /// Same end-to-end check, but driven through the split [`ideal_rot_pair`]
    /// sources (the consume-from-pool boundary the upper layers use).
    #[test]
    fn cot_relation_holds_via_split_sources() {
        use crate::dhim::{
            rot::{RotReceiverSource, RotSenderSource},
            test_utils::ideal_rot_pair,
        };

        let (mut send, mut recv) = ideal_rot_pair([5u8; 16]);
        for &p in &[5u64, 97, 1009, 1063] {
            for k in 0..(2 * p) {
                let delta = k % p;
                let choice = (k / p) % 2 == 1;

                let s_share = send.next_sender(p);
                let r_share = recv.next_receiver(p);
                let f = receiver_flip(&r_share, choice);
                let (a0, corr) = sender_step(s_share, delta, f, p);
                let out = receiver_output(r_share, choice, corr, p);

                assert_eq!(out, (a0 + (choice as u64 * delta) % p) % p);
            }
        }
    }
}
