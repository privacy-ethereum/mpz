//! Weak multiplication receiver.

use rand::Rng;

use crate::dhim::rot::{RotReceiverShare, RotReceiverSource};

use super::{
    ReceiverMsg, SenderMsg, Tau, ceil_log2,
    cot::{self, Correction},
};

/// Weak multiplication receiver.
pub(crate) struct Receiver {
    /// Receiver input residue `x` (`x < p`).
    x: u64,
    /// The prime modulus.
    p: u64,
    /// Bit permutation `τ` (see [`Tau`]).
    tau: Tau,
    /// Chosen bits `λ`.
    choices: Vec<bool>,
    // Consumed ROT shares.
    rot: Vec<RotReceiverShare>,
    /// Which step is expected next.
    state: ReceiverState,
}

impl Receiver {
    /// Creates a `Wmult_p` receiver.
    ///
    /// # Arguments
    ///
    /// * `x` — the receiver's input residue, `x < p`.
    /// * `p` — the CRT prime modulus this Wmult operates over.
    /// * `tau` — the precomputed bit permutation `τ` (must have `⌈log₂ p⌉`
    ///   entries).
    pub(crate) fn new(x: u64, p: u64, tau: Tau) -> Self {
        debug_assert!(x < p);
        debug_assert_eq!(tau.len(), ceil_log2(p) as usize, "τ must have ℓ entries");
        Self {
            x,
            p,
            tau,
            choices: Vec::new(),
            rot: Vec::new(),
            state: ReceiverState::Initialized,
        }
    }

    /// Allocates resources.
    pub(crate) fn alloc<S: RotReceiverSource>(&mut self, rot: &mut S) -> Result<(), ReceiverError> {
        self.check_state(ReceiverState::Initialized)?;
        rot.alloc(ceil_log2(self.p) as usize);
        self.state = ReceiverState::Allocated;
        Ok(())
    }

    /// Builds the receiver's request.
    pub(crate) fn request<S: RotReceiverSource, R: Rng + ?Sized>(
        &mut self,
        rot: &mut S,
        rng: &mut R,
    ) -> Result<ReceiverMsg, ReceiverError> {
        self.check_state(ReceiverState::Allocated)?;

        let l = self.tau.len();

        // Step 1a: choose c. If x + p ≥ 2^ℓ, c must be 0 to keep x + c·p < 2^ℓ;
        // otherwise c is a uniform bit drawn from the private RNG.
        let pow_l = 1u64 << l;
        let c = if self.x + self.p >= pow_l {
            0
        } else {
            rng.random::<bool>() as u64
        };
        let value = self.x + c * self.p; // < 2^ℓ, so it fits in ℓ bits

        // Step 1b: reshuffle the bits of `value` into τ-permuted order.
        let choices = self.tau.permuted_bits(value);

        // Consume ℓ ROT receiver-shares and form the COT flip bits.
        let mut rot_shares = Vec::with_capacity(l);
        let mut flips = Vec::with_capacity(l);
        for &choice in &choices {
            let share = rot.next_receiver(self.p);
            flips.push(cot::receiver_flip(&share, choice));
            rot_shares.push(share);
        }

        self.choices = choices;
        self.rot = rot_shares;
        self.state = ReceiverState::Requested;
        Ok(ReceiverMsg { flips })
    }

    /// Finishes the protocol and returns the output. Consumes the receiver.
    pub(crate) fn finish(self, msg: &SenderMsg) -> Result<u64, ReceiverError> {
        self.check_state(ReceiverState::Requested)?;

        let l = self.tau.len();
        if msg.corrections.len() != l {
            return Err(ReceiverError::CorrectionCount {
                expected: l,
                found: msg.corrections.len(),
            });
        }

        // Accumulate Σᵢ 2^{τ(i)}·zᵢ raw and reduce once: weights are distinct
        // powers of two summing to 2^ℓ−1 and each zᵢ < p, so the sum is bounded
        // by (2^ℓ−1)(p−1) < 2²² ≪ 2⁶⁴ — no overflow, no per-term reduction.
        let mut acc = 0u64;
        for i in 0..l {
            let z_i = cot::receiver_output(
                self.rot[i],
                self.choices[i],
                Correction {
                    o: msg.corrections[i],
                },
                self.p,
            );
            acc += self.tau.weight(i) * z_i;
        }
        Ok(acc % self.p)
    }

    /// Errors with `OutOfOrder` unless the receiver is in `expected`.
    fn check_state(&self, expected: ReceiverState) -> Result<(), ReceiverError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(ReceiverError::OutOfOrder {
                expected: expected.name(),
                found: self.state.name(),
            })
        }
    }
}

/// Where a [`Receiver`] is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiverState {
    Initialized,
    Allocated,
    Requested,
}

impl ReceiverState {
    const fn name(self) -> &'static str {
        match self {
            ReceiverState::Initialized => "initialized",
            ReceiverState::Allocated => "allocated",
            ReceiverState::Requested => "requested",
        }
    }
}

/// Error returned by a [`Receiver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverError {
    /// A step was called in the wrong state: the method required state
    /// `expected`, but the receiver was at `found`.
    OutOfOrder {
        /// Name of the state the called step required.
        expected: &'static str,
        /// Name of the state the receiver was actually in.
        found: &'static str,
    },
    /// The sender's response carried the wrong number of corrections.
    CorrectionCount {
        /// `ℓ`, the number of corrections the prime requires.
        expected: usize,
        /// The number of corrections the response carried.
        found: usize,
    },
}

impl std::fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiverError::OutOfOrder { expected, found } => write!(
                f,
                "Wmult receiver called out of order: expected state `{expected}`, was at `{found}`"
            ),
            ReceiverError::CorrectionCount { expected, found } => write!(
                f,
                "Wmult response carried {found} corrections, expected ℓ = {expected}"
            ),
        }
    }
}

impl std::error::Error for ReceiverError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::{test_utils::ideal_rot_pair, wmult::derive_taus};
    use mpz_core::prg::Prg;

    /// Drives a receiver to the `Requested` state over an ideal ROT stream.
    fn requested(p: u64) -> Receiver {
        let tau = derive_taus([7u8; 16], &[p]).remove(0);
        let (_send, mut recv) = ideal_rot_pair([7u8; 16]);
        let mut rng = Prg::new_with_seed([9u8; 16]);
        let mut receiver = Receiver::new(5, p, tau);
        receiver.alloc(&mut recv).expect("alloc");
        receiver.request(&mut recv, &mut rng).expect("request");
        receiver
    }

    /// A response with the wrong number of corrections is rejected — once the
    /// receiver has actually issued its request.
    #[test]
    fn finish_rejects_wrong_correction_count() {
        let p = 1063u64; // ℓ = 11
        for found in [0usize, 10, 12] {
            let receiver = requested(p);
            let bad = SenderMsg {
                corrections: vec![0; found],
            };
            assert_eq!(
                receiver.finish(&bad).unwrap_err(),
                ReceiverError::CorrectionCount {
                    expected: 11,
                    found,
                }
            );
        }
    }

    /// `request` requires `Allocated`, `finish` requires `Requested`, and
    /// `alloc` is a one-shot `Initialized → Allocated` transition.
    #[test]
    fn steps_are_state_guarded() {
        let p = 1063u64;
        let tau = derive_taus([2u8; 16], &[p]).remove(0);
        let (_send, mut recv) = ideal_rot_pair([4u8; 16]);
        let mut rng = Prg::new_with_seed([5u8; 16]);
        let mut receiver = Receiver::new(3, p, tau);

        // request before alloc.
        assert_eq!(
            receiver.request(&mut recv, &mut rng).unwrap_err(),
            ReceiverError::OutOfOrder {
                expected: "allocated",
                found: "initialized",
            }
        );

        receiver.alloc(&mut recv).expect("alloc");

        // second alloc.
        assert_eq!(
            receiver.alloc(&mut recv).unwrap_err(),
            ReceiverError::OutOfOrder {
                expected: "initialized",
                found: "allocated",
            }
        );

        // finish before request (consumes the receiver).
        let bad = SenderMsg {
            corrections: vec![0; 11],
        };
        assert_eq!(
            receiver.finish(&bad).unwrap_err(),
            ReceiverError::OutOfOrder {
                expected: "requested",
                found: "allocated",
            }
        );
    }
}
