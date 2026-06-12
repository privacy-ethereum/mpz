//! Weak multiplication sender.

use crate::dhim::rot::RotSenderSource;

use super::{ReceiverMsg, SenderMsg, Tau, ceil_log2, cot, zp};

/// Weak multiplication sender.
pub(crate) struct Sender {
    /// Sender input residue `a` (`a < p`).
    a: u64,
    /// The prime modulus.
    p: u64,
    /// Per-slot COT pads `δᵢ`, stored by [`Sender::respond`] until `τ`
    /// arrives and [`Sender::output`] consumes them.
    pads: Vec<u64>,
    /// Which step is expected next.
    state: SenderState,
}

impl Sender {
    /// Creates a new sender.
    ///
    /// # Arguments
    ///
    /// * `a` — the sender's input residue, `a < p`.
    /// * `p` — the CRT prime modulus.
    pub(crate) fn new(a: u64, p: u64) -> Self {
        debug_assert!(a < p);
        Self {
            a,
            p,
            pads: Vec::new(),
            state: SenderState::Initialized,
        }
    }

    /// Allocates resources.
    ///
    /// # Errors
    ///
    /// [`SenderError::OutOfOrder`] unless the sender is freshly initialized.
    pub(crate) fn alloc<S: RotSenderSource>(&mut self, rot: &mut S) -> Result<(), SenderError> {
        self.check_state(SenderState::Initialized)?;

        rot.alloc(ceil_log2(self.p) as usize);
        self.state = SenderState::Allocated;
        Ok(())
    }

    /// Processes the receiver request, returning the message for the
    /// receiver.
    ///
    /// # Arguments
    ///
    /// * `rot` — the ROT sender-share source.
    /// * `msg` — the receiver's request ([`ReceiverMsg`]).
    pub(crate) fn respond<S: RotSenderSource>(
        &mut self,
        rot: &mut S,
        msg: &ReceiverMsg,
    ) -> Result<SenderMsg, SenderError> {
        self.check_state(SenderState::Allocated)?;

        let l = ceil_log2(self.p) as usize;
        if msg.flips.len() != l {
            self.state = SenderState::Failed;
            return Err(SenderError::FlipCount {
                expected: l,
                found: msg.flips.len(),
            });
        }

        let mut corrections = Vec::with_capacity(l);
        let mut pads = Vec::with_capacity(l);
        for i in 0..l {
            let share = rot.next_sender(self.p);
            // COT_p with sender offset δ = a; δ_i is the returned random pad.
            let (delta_i, corr) = cot::sender_step(share, self.a, msg.flips[i], self.p);
            corrections.push(corr.o);
            pads.push(delta_i);
        }

        self.pads = pads;
        self.state = SenderState::Responded;
        Ok(SenderMsg { corrections })
    }

    /// Computes the sender's output `z_S = −Σᵢ 2^{τ(i)}·δᵢ mod p`.
    ///
    /// # Panics
    ///
    /// Panics if `tau` does not have exactly `ℓ` entries.
    pub(crate) fn output(&self, tau: &Tau) -> Result<u64, SenderError> {
        self.check_state(SenderState::Responded)?;

        let l = ceil_log2(self.p) as usize;
        assert_eq!(tau.len(), l, "τ must have ℓ entries");

        // Accumulate Σᵢ 2^{τ(i)}·δᵢ raw, then reduce and negate once: weights
        // are distinct powers of two summing to 2^ℓ−1 and each δᵢ < p, so the
        // sum is bounded by (2^ℓ−1)(p−1) < 2²² ≪ 2⁶⁴ — no overflow, no
        // per-term reduction.
        let mut acc = 0u64;
        for (i, &delta_i) in self.pads.iter().enumerate() {
            acc += tau.weight(i) * delta_i; // 2^{τ(i)}·δ_i, raw
        }
        Ok(zp::neg(acc % self.p, self.p)) // −Σ mod p
    }

    /// Errors with `OutOfOrder` unless the sender is in `expected`.
    fn check_state(&self, expected: SenderState) -> Result<(), SenderError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(SenderError::OutOfOrder {
                expected: expected.name(),
                found: self.state.name(),
            })
        }
    }
}

/// Where a [`Sender`] is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SenderState {
    Initialized,
    Allocated,
    Responded,
    Failed,
}

impl SenderState {
    const fn name(self) -> &'static str {
        match self {
            SenderState::Initialized => "initialized",
            SenderState::Allocated => "allocated",
            SenderState::Responded => "responded",
            SenderState::Failed => "failed",
        }
    }
}

/// Error returned by a [`Sender`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SenderError {
    /// A step was called in the wrong state: the method required state
    /// `expected`, but the sender was at `found`.
    OutOfOrder {
        /// Name of the state the called step required.
        expected: &'static str,
        /// Name of the state the sender was actually in.
        found: &'static str,
    },
    /// The receiver's request carried the wrong number of flip bits.
    FlipCount {
        /// `ℓ`, the number of flip bits the prime requires.
        expected: usize,
        /// The number of flip bits the request carried.
        found: usize,
    },
}

impl std::fmt::Display for SenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SenderError::OutOfOrder { expected, found } => write!(
                f,
                "Wmult sender called out of order: expected state `{expected}`, was at `{found}`"
            ),
            SenderError::FlipCount { expected, found } => write!(
                f,
                "Wmult request carried {found} flip bits, expected ℓ = {expected}"
            ),
        }
    }
}

impl std::error::Error for SenderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::{test_utils::ideal_rot_pair, wmult::derive_taus};

    /// A request with the wrong number of flips is rejected — before any ROT
    /// share is consumed — and poisons the sender, so `output` is then
    /// rejected as out-of-order. A fresh sender is used per case since the
    /// first rejection is terminal.
    #[test]
    fn respond_rejects_wrong_flip_count() {
        let p = 1063u64; // ℓ = 11
        let tau = derive_taus([1u8; 16], &[p]).remove(0);
        for found in [0usize, 10, 12] {
            let (mut send, _recv) = ideal_rot_pair([3u8; 16]);
            let mut sender = Sender::new(42, p);
            sender.alloc(&mut send).expect("alloc");

            let bad = ReceiverMsg {
                flips: vec![false; found],
            };
            assert_eq!(
                sender.respond(&mut send, &bad).unwrap_err(),
                SenderError::FlipCount {
                    expected: 11,
                    found,
                }
            );
            assert_eq!(
                sender.output(&tau).unwrap_err(),
                SenderError::OutOfOrder {
                    expected: "responded",
                    found: "failed",
                }
            );
        }
    }

    /// `respond` requires `Allocated`, `output` requires `Responded`, and
    /// `alloc` is a one-shot `Initialized → Allocated` transition.
    #[test]
    fn steps_are_state_guarded() {
        let p = 1063u64;
        let (mut send, _recv) = ideal_rot_pair([4u8; 16]);
        let mut sender = Sender::new(7, p);
        let tau = derive_taus([2u8; 16], &[p]).remove(0);

        // respond before alloc.
        let msg = ReceiverMsg {
            flips: vec![false; 11],
        };
        assert_eq!(
            sender.respond(&mut send, &msg).unwrap_err(),
            SenderError::OutOfOrder {
                expected: "allocated",
                found: "initialized",
            }
        );

        // output before respond.
        sender.alloc(&mut send).expect("alloc");
        assert_eq!(
            sender.output(&tau).unwrap_err(),
            SenderError::OutOfOrder {
                expected: "responded",
                found: "allocated",
            }
        );

        // second alloc.
        assert_eq!(
            sender.alloc(&mut send).unwrap_err(),
            SenderError::OutOfOrder {
                expected: "initialized",
                found: "allocated",
            }
        );
    }
}
