//! OLE Sender.

use crypto_bigint::BoxedUint;
use mpz_core::hash::Hash;
use mpz_fields::Field;
use rand::Rng;

use crate::dhim::{config::Config, rot::RotSenderSource};

use super::{ring::Ring, wmult};

use super::{
    Round1Recv, Round1Send, Round2Recv, Round2Send, Round3Recv, Round3Send, random_bits,
    reduce_to_field,
};

/// OLE Sender.
pub struct OleSender<F> {
    /// Protocol config.
    config: &'static Config,
    /// Input mask `a'`.
    a_prime: BoxedUint,
    /// `a'` reduced into `F`.
    a_prime_mod_q: F,
    /// One `Wmult` sender per prime.
    wmults: Vec<wmult::Sender>,
    /// oˢ.
    o_s: Option<BoxedUint>,
    /// The receiver's commitment to `(x'_p, oᴿ_p)`.
    commitment: Option<Hash>,
    /// Which round is expected next.
    state: SenderState,
}

impl<F: Field> OleSender<F> {
    /// Initializes the sender.
    pub fn new<R: Rng + ?Sized>(config: &'static Config, rng: &mut R) -> Self {
        let basis = config.crt;
        // a' ←$ [0, 2^|s_a|): wide mask hiding a ∈ Z_q.
        let a_prime = random_bits(rng, config.params.s_a_bits, basis.precision());

        let a_res = basis.encode(&a_prime);
        // Reduce a' into F (a' mod q).
        let a_prime_mod_q = reduce_to_field::<F>(&a_prime, config.q);

        // Build one `Wmult` sender per prime.
        let wmults = basis
            .primes()
            .iter()
            .zip(a_res)
            .map(|(&p, a)| wmult::Sender::new(a, p))
            .collect();
        Self {
            config,
            a_prime,
            a_prime_mod_q,
            wmults,
            o_s: None,
            commitment: None,
            state: SenderState::Initialized,
        }
    }

    /// Allocates resources.
    pub fn alloc<SS: RotSenderSource>(&mut self, rot: &mut SS) -> Result<(), OleSenderError> {
        self.check_state(SenderState::Initialized)?;
        for w in &mut self.wmults {
            w.alloc(rot)?;
        }
        self.state = SenderState::Allocated;
        Ok(())
    }

    /// Runs round 1 and returns a message to send.
    pub fn round1<SS>(
        &mut self,
        rot: &mut SS,
        msg: &Round1Recv,
    ) -> Result<Round1Send, OleSenderError>
    where
        SS: RotSenderSource,
    {
        self.check_state(SenderState::Allocated)?;

        // Unpack the flattened flips into one request per prime (one blob-length
        // check, in place of the old per-prime count guard).
        let recv_msgs = match msg.unpack(self.config.crt) {
            Ok(v) => v,
            Err(e) => {
                self.state = SenderState::Failed;
                return Err(e.into());
            }
        };

        // Protocol 5.14 step 3 (OT phase of Protocol 5.11): produce the COT
        // corrections. `τ` is not yet known — the receiver reveals it only
        // after these corrections are fixed (Protocol 5.11 step 3) — so oˢ is
        // deferred to round 2; each `Wmult` keeps its pads internally.
        let mut send_msgs = Vec::with_capacity(self.wmults.len());
        for (w, m_in) in self.wmults.iter_mut().zip(recv_msgs.iter()) {
            let m = match w.respond(rot, m_in) {
                Ok(m) => m,
                Err(e) => {
                    // Poison: ROT shares may already be consumed, so the
                    // sender cannot meaningfully retry this round.
                    self.state = SenderState::Failed;
                    return Err(e.into());
                }
            };
            send_msgs.push(m);
        }

        self.state = SenderState::Round2;
        Ok(Round1Send::pack(&send_msgs, self.config.crt))
    }

    /// Runs round 2 and returns a message to send.
    pub fn round2(&mut self, msg: &Round2Recv) -> Result<Round2Send, OleSenderError> {
        self.check_state(SenderState::Round2)?;

        let basis = self.config.crt;

        // Protocol 5.11 step 3: `τ` arrives now that the corrections are
        // fixed; compute oˢ (Protocol 5.14 step 3).
        let taus = wmult::derive_taus(msg.tau_seed, basis.primes());
        let os_res: Result<Vec<u64>, _> = self
            .wmults
            .iter()
            .zip(&taus)
            .map(|(w, tau)| w.output(tau))
            .collect();
        let os_res = match os_res {
            Ok(v) => v,
            Err(e) => {
                self.state = SenderState::Failed;
                return Err(e.into());
            }
        };
        let o_s = basis.decode(&os_res);

        // Protocol 5.14 step 6 and Protocol 5.38 step 3.
        let ring_r = Ring::new(msg.r.clone());
        let os_mod_r = ring_r.from_uint(&o_s).to_uint();
        let a_prime_mod_r = ring_r.from_uint(&self.a_prime).to_uint();

        self.o_s = Some(o_s);

        self.commitment = Some(msg.commitment);

        self.state = SenderState::Round3;
        Ok(Round2Send {
            os_mod_r,
            a_prime_mod_r,
        })
    }

    /// Runs round 3 and returns a message to send.
    pub fn round3(self, a: F, b: F, msg: &Round3Recv<F>) -> Result<Round3Send<F>, OleSenderError> {
        self.check_state(SenderState::Round3)?;
        let q = self.config.q;
        let crt = self.config.crt;
        let o_s = self.o_s.expect("round2 must run first");

        // Protocol 5.14 step 8a.
        let commitment = self.commitment.expect("round2 must run first");
        msg.opening
            .verify(&commitment)
            .map_err(|_| OleSenderError::ConsistencyCheck)?;
        let (x_p_bytes, o_r_p_bytes) = msg.opening.data();
        let ring_p = Ring::new(self.config.p.clone());
        let prec = self.config.p.bits_precision();

        // Reduce the opened residues into Z_p; reject ill-formed bytes rather than
        // panic.
        let x_p = ring_p.from_uint(
            &BoxedUint::from_be_slice(x_p_bytes, prec)
                .map_err(|_| OleSenderError::ConsistencyCheck)?,
        );
        let o_r_p = ring_p.from_uint(
            &BoxedUint::from_be_slice(o_r_p_bytes, prec)
                .map_err(|_| OleSenderError::ConsistencyCheck)?,
        );
        let lhs = &(&o_r_p + &ring_p.from_uint(&o_s)) - &(&ring_p.from_uint(&self.a_prime) * &x_p);
        if lhs != ring_p.zero() && lhs != ring_p.from_uint(crt.modulus()) {
            return Err(OleSenderError::ConsistencyCheck);
        }

        // a' mod q was reduced into F back in `new`.
        let a_prime_f = self.a_prime_mod_q;
        // The line (a, b) enters here: δ_a = a − a', δ_b = b + oˢ + a'·δ_x.
        let delta_a = a - a_prime_f;
        let delta_b = b + reduce_to_field::<F>(&o_s, q) + a_prime_f * msg.delta_x;
        Ok(Round3Send { delta_a, delta_b })
    }

    /// Errors with `OutOfOrder` unless the sender is in `expected`.
    fn check_state(&self, expected: SenderState) -> Result<(), OleSenderError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(OleSenderError::OutOfOrder {
                expected: expected.name(),
                found: self.state.name(),
            })
        }
    }
}

/// Where an [`OleSender`] is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SenderState {
    Initialized,
    Allocated,
    Round2,
    Round3,
    Failed,
}

impl SenderState {
    const fn name(self) -> &'static str {
        match self {
            SenderState::Initialized => "initialized",
            SenderState::Allocated => "allocated",
            SenderState::Round2 => "round2",
            SenderState::Round3 => "round3",
            SenderState::Failed => "failed",
        }
    }
}

/// Error returned by an [`OleSender`] round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OleSenderError {
    /// A round was called in the wrong state: the method required state
    /// `expected`, but the sender was at `found`.
    OutOfOrder {
        /// Name of the state the called round required.
        expected: &'static str,
        /// Name of the state the sender was actually in.
        found: &'static str,
    },
    /// The receiver's round-1 message could not be unpacked (wrong blob
    /// length for the CRT prime set).
    Pack(crate::dhim::PackError),
    /// A per-prime `Wmult` rejected the receiver's request.
    Wmult(wmult::SenderError),
    /// The mod-`p` consistency check (step 8a) failed.
    ConsistencyCheck,
}

impl From<wmult::SenderError> for OleSenderError {
    fn from(e: wmult::SenderError) -> Self {
        OleSenderError::Wmult(e)
    }
}

impl From<crate::dhim::PackError> for OleSenderError {
    fn from(e: crate::dhim::PackError) -> Self {
        OleSenderError::Pack(e)
    }
}

impl std::fmt::Display for OleSenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OleSenderError::OutOfOrder { expected, found } => write!(
                f,
                "OLE sender called out of order: expected state `{expected}`, was at `{found}`"
            ),
            OleSenderError::Pack(e) => write!(f, "OLE round-1 message malformed: {e}"),
            OleSenderError::Wmult(e) => write!(f, "OLE Wmult failed: {e}"),
            OleSenderError::ConsistencyCheck => write!(f, "OLE consistency check failed"),
        }
    }
}

impl std::error::Error for OleSenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OleSenderError::Pack(e) => Some(e),
            OleSenderError::Wmult(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::{
        OleReceiver, ReceiverResidues,
        rot::{BlockToZpReceiver, BlockToZpSender},
        test_utils::{preflushed_ideal_rot, rots_per_ole},
    };
    use mpz_core::commit::HashCommit;
    use mpz_fields::p256::P256;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// A fresh sender in the `Initialized` state plus an (unconsumed) ROT
    /// source, for exercising the state-machine guards in isolation.
    fn fresh_sender(seed: u64) -> (OleSender<P256>, impl RotSenderSource) {
        let cfg = crate::dhim::config::p256::config();
        let count = rots_per_ole(cfg);
        let (s_inner, _r) = preflushed_ideal_rot([seed as u8; 16], count);
        let rot = BlockToZpSender::new(s_inner);
        let mut srng = ChaCha20Rng::seed_from_u64(seed);
        let sender = OleSender::<P256>::new(cfg, &mut srng);
        (sender, rot)
    }

    /// `round1` requires `Allocated`; calling it straight after `new` is
    /// rejected (the guard fires before the message or ROT source is
    /// touched).
    #[test]
    fn round1_before_alloc_is_out_of_order() {
        let (mut sender, mut rot) = fresh_sender(21);
        let dummy = Round1Recv { flips: Vec::new() };
        assert_eq!(
            sender.round1(&mut rot, &dummy).unwrap_err(),
            OleSenderError::OutOfOrder {
                expected: "allocated",
                found: "initialized",
            }
        );
    }

    /// `alloc` is a one-shot `Initialized → Allocated` transition; a second
    /// call is rejected.
    #[test]
    fn alloc_twice_is_out_of_order() {
        let (mut sender, mut rot) = fresh_sender(22);
        sender.alloc(&mut rot).expect("first alloc succeeds");
        assert_eq!(
            sender.alloc(&mut rot).unwrap_err(),
            OleSenderError::OutOfOrder {
                expected: "initialized",
                found: "allocated",
            }
        );
    }

    /// A round-1 flips blob of the wrong length is rejected with
    /// `Pack(WrongLength)`, and the sender is poisoned (no partial ROT
    /// consumption can be retried).
    #[test]
    fn round1_rejects_wrong_flip_length() {
        use crate::dhim::{PackError, wmult::ceil_log2};

        let (mut sender, mut rot) = fresh_sender(25);
        sender.alloc(&mut rot).expect("alloc succeeds");

        let cfg = crate::dhim::config::p256::config();
        let expected = cfg
            .crt
            .primes()
            .iter()
            .map(|&p| ceil_log2(p) as usize)
            .sum::<usize>()
            .div_ceil(8);
        let short = Round1Recv { flips: Vec::new() };
        assert_eq!(
            sender.round1(&mut rot, &short).unwrap_err(),
            OleSenderError::Pack(PackError::WrongLength { expected, found: 0 })
        );
        assert_eq!(
            sender.round1(&mut rot, &short).unwrap_err(),
            OleSenderError::OutOfOrder {
                expected: "allocated",
                found: "failed",
            }
        );
    }

    /// `round2` requires `Round2`; calling it before `round1` is rejected.
    #[test]
    fn round2_before_round1_is_out_of_order() {
        let (mut sender, _rot) = fresh_sender(23);
        let dummy = Round2Recv {
            r: BoxedUint::from(5u64),
            commitment: mpz_core::hash::Hash::from([0u8; 32]),
            tau_seed: [0u8; 16],
        };
        assert_eq!(
            sender.round2(&dummy).unwrap_err(),
            OleSenderError::OutOfOrder {
                expected: "round2",
                found: "initialized",
            }
        );
    }

    /// `round3` requires `Round3`; calling it before `round2` is rejected (it
    /// consumes `self`, so this is a one-shot check).
    #[test]
    fn round3_before_round2_is_out_of_order() {
        let (sender, _rot) = fresh_sender(24);
        let dummy = Round3Recv {
            delta_x: P256::zero(),
            opening: mpz_core::commit::Decommitment::new((Vec::new(), Vec::new())),
        };
        assert_eq!(
            sender
                .round3(P256::zero(), P256::zero(), &dummy)
                .unwrap_err(),
            OleSenderError::OutOfOrder {
                expected: "round3",
                found: "initialized",
            }
        );
    }

    /// Drives an honest sender+receiver through flight 4, returning the sender
    /// poised at `round3` (with the receiver's genuine commitment stashed), the
    /// receiver poised at `round3`, and the sender's flight-4 message `m4`.
    fn drive_to_round3(seed: u64) -> (OleSender<P256>, OleReceiver<P256>, Round2Send) {
        let cfg = crate::dhim::config::p256::config();
        let count = rots_per_ole(cfg);
        let (s_inner, r_inner) = preflushed_ideal_rot([seed as u8; 16], count);
        let mut s_rot = BlockToZpSender::new(s_inner);
        let mut r_rot = BlockToZpReceiver::new(r_inner);
        let mut srng = ChaCha20Rng::seed_from_u64(1000 + seed);
        let mut rrng = ChaCha20Rng::seed_from_u64(2000 + seed);

        let mut sender = OleSender::<P256>::new(cfg, &mut srng);
        let mut receiver = OleReceiver::<P256>::new(cfg, &mut rrng);
        sender.alloc(&mut s_rot).expect("sender alloc");
        receiver.alloc(&mut r_rot).expect("receiver alloc");

        let m1 = receiver.round1(&mut r_rot).expect("receiver round1");
        let m2 = sender.round1(&mut s_rot, &m1).expect("sender round1");
        let m3 = receiver.round2(&m2).expect("receiver round2");
        let m4 = sender.round2(&m3).expect("sender round2"); // stashes the genuine commitment
        (sender, receiver, m4)
    }

    /// Step 8a (binding): an opening that doesn't match the receiver's round-2
    /// commitment is rejected — a malicious receiver can't swap in different
    /// `(x'_p, oᴿ_p)` after committing.
    #[test]
    fn step8a_rejects_opening_mismatching_commitment() {
        let (sender, mut receiver, m4) = drive_to_round3(7);
        let m5 = receiver.round3(P256::zero(), &m4).expect("receiver round3");

        // Re-commit to *different* residues; its commitment won't match the one
        // the sender stashed, so the opening fails to verify.
        let other: ReceiverResidues = (vec![9u8; 8], vec![9u8; 8]);
        let (other_opening, _) = other.hash_commit();
        let tampered = Round3Recv {
            delta_x: m5.delta_x,
            opening: other_opening,
        };
        assert_eq!(
            sender
                .round3(P256::zero(), P256::zero(), &tampered)
                .unwrap_err(),
            OleSenderError::ConsistencyCheck
        );
    }

    /// Step 8a (arithmetic): a *validly opened* commitment to residues that
    /// violate `oᴿ_p + oˢ − a'·x'_p ∈ {0, n} mod p` is rejected — the
    /// malicious-receiver (large-input) defense. We inject a commitment to
    /// bogus residues `(x'_p, oᴿ_p) = (1, 1)` and open it honestly.
    #[test]
    fn step8a_rejects_inconsistent_residues() {
        let cfg = crate::dhim::config::p256::config();
        let count = rots_per_ole(cfg);
        let (s_inner, r_inner) = preflushed_ideal_rot([8u8; 16], count);
        let mut s_rot = BlockToZpSender::new(s_inner);
        let mut r_rot = BlockToZpReceiver::new(r_inner);
        let mut srng = ChaCha20Rng::seed_from_u64(8);
        let mut rrng = ChaCha20Rng::seed_from_u64(108);

        let mut sender = OleSender::<P256>::new(cfg, &mut srng);
        let mut receiver = OleReceiver::<P256>::new(cfg, &mut rrng);
        sender.alloc(&mut s_rot).unwrap();
        receiver.alloc(&mut r_rot).unwrap();

        let m1 = receiver.round1(&mut r_rot).unwrap();
        let m2 = sender.round1(&mut s_rot, &m1).unwrap();
        let m3 = receiver.round2(&m2).unwrap();

        // Inject a commitment to bogus residues (1, 1); the sender stashes it.
        let bogus: ReceiverResidues = (1u64.to_be_bytes().to_vec(), 1u64.to_be_bytes().to_vec());
        let (opening, commitment) = bogus.hash_commit();
        let m3_bad = Round2Recv {
            r: m3.r.clone(),
            commitment,
            tau_seed: m3.tau_seed,
        };
        sender.round2(&m3_bad).unwrap();

        let m5_bad = Round3Recv {
            delta_x: P256::zero(),
            opening,
        };
        assert_eq!(
            sender
                .round3(P256::zero(), P256::zero(), &m5_bad)
                .unwrap_err(),
            OleSenderError::ConsistencyCheck
        );
    }
}
