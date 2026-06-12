//! OLE Receiver.

use crypto_bigint::BoxedUint;
use mpz_core::{
    commit::{Decommitment, HashCommit},
    prg::Prg,
};
use mpz_fields::Field;
use rand::CryptoRng;

use crate::dhim::{config::Config, rot::RotReceiverSource};

use super::{ring::Ring, sampler, wmult};

use super::{
    ReceiverResidues, Round1Recv, Round1Send, Round2Recv, Round2Send, Round3Recv, Round3Send,
    random_bits, reduce_to_field,
};

/// OLE Receiver.
pub struct OleReceiver<F> {
    /// Protocol config.
    config: &'static Config,
    /// The receiver's input point `x`.
    x: Option<F>,
    /// Input mask `x'`.
    x_prime: BoxedUint,
    /// `x'` reduced into `F` (i.e. `x' mod q`).
    x_prime_mod_q: F,
    /// Master `τ` seed.
    tau_seed: [u8; 16],
    /// Private PRG, that supplies each `Wmult`'s secret bit `c`.
    c_rng: Prg,
    /// One `Wmult` receiver per prime.
    wmults: Vec<wmult::Receiver>,
    /// oᴿ.
    o_r: Option<BoxedUint>,
    /// Decommitment to `(x'_p, oᴿ_p)`.
    opening: Option<Decommitment<ReceiverResidues>>,
    /// Consistency prime `r`.
    r: BoxedUint,
    /// The wrap correction `f ∈ {0, n}`, already reduced into `F`.
    f_q: Option<F>,
    /// Which round is expected next.
    state: RoundState,
}

impl<F: Field> OleReceiver<F> {
    /// Initializes the receiver.
    pub fn new<R: CryptoRng + ?Sized>(config: &'static Config, rng: &mut R) -> Self {
        let basis = config.crt;
        // x' ←$ [0, 2^|s_x|): wide mask hiding x ∈ Z_q (revealed only as δ_x).
        let x_prime = random_bits(rng, config.params.s_x_bits, basis.precision());
        // r ←$ P_{s_r} \ {q}: the fresh consistency prime.
        let r = sampler::sample_random_prime(rng, config.params.s_r_bits, config.q);

        let x_res = basis.encode(&x_prime);
        // Reduce x' into F (x' mod q).
        let x_prime_mod_q = reduce_to_field::<F>(&x_prime, config.q);

        // The receiver owns the τ entropy: it picks one master seed here and
        // expands it into every per-prime permutation. Only this seed crosses
        // the wire (in flight 3). The per-instance τ is then handed down into
        // each `wmult::Receiver`; see `wmult::derive_taus` for why the seam
        // sits at this layer rather than inside Wmult.
        let mut tau_seed = [0u8; 16];
        rng.fill_bytes(&mut tau_seed);
        let taus = wmult::derive_taus(tau_seed, basis.primes());

        // Build one `Wmult` receiver per prime.
        let wmults = basis
            .primes()
            .iter()
            .zip(x_res)
            .zip(taus)
            .map(|((&p, x), tau)| wmult::Receiver::new(x, p, tau))
            .collect();

        let mut c_seed = [0u8; 16];
        rng.fill_bytes(&mut c_seed);
        let c_rng = Prg::new_with_seed(c_seed);
        Self {
            config,
            x: None,
            x_prime,
            x_prime_mod_q,
            tau_seed,
            c_rng,
            wmults,
            o_r: None,
            opening: None,
            r,
            f_q: None,
            state: RoundState::Initialized,
        }
    }

    /// Allocates resources.
    pub fn alloc<RS: RotReceiverSource>(&mut self, rot: &mut RS) -> Result<(), OleReceiverError> {
        self.check_state(RoundState::Initialized)?;
        for w in &mut self.wmults {
            w.alloc(rot)?;
        }
        self.state = RoundState::Allocated;
        Ok(())
    }

    /// Runs round 1 and returns a message to send.
    pub fn round1<RS>(&mut self, rot: &mut RS) -> Result<Round1Recv, OleReceiverError>
    where
        RS: RotReceiverSource,
    {
        self.check_state(RoundState::Allocated)?;

        // Protocol 5.14 step 3.
        let mut wmults = std::mem::take(&mut self.wmults);
        let mut recv_msgs = Vec::with_capacity(wmults.len());
        for w in &mut wmults {
            match w.request(rot, &mut self.c_rng) {
                Ok(m) => recv_msgs.push(m),
                Err(e) => {
                    // Poison: ROT shares may already be consumed, so the
                    // receiver cannot meaningfully retry this round.
                    self.state = RoundState::Failed;
                    return Err(e.into());
                }
            }
        }
        self.wmults = wmults;
        self.state = RoundState::Round2;
        Ok(Round1Recv::pack(&recv_msgs))
    }

    /// Runs round 2 and returns a message to send.
    pub fn round2(&mut self, msg: &Round1Send) -> Result<Round2Recv, OleReceiverError> {
        self.check_state(RoundState::Round2)?;

        let basis = self.config.crt;

        // Unpack the flattened corrections into one response per prime (one
        // blob-length check, in place of the old per-prime count guard).
        let send_msgs = match msg.unpack(basis) {
            Ok(v) => v,
            Err(e) => {
                self.state = RoundState::Failed;
                return Err(e.into());
            }
        };

        let wmults = std::mem::take(&mut self.wmults);
        let mut or_res = Vec::with_capacity(wmults.len());

        // Protocol 5.14 step 3.
        for (w, m) in wmults.into_iter().zip(send_msgs.iter()) {
            match w.finish(m) {
                Ok(z) => or_res.push(z),
                Err(e) => {
                    // Poison: the per-prime receivers are consumed, so this
                    // round cannot be retried.
                    self.state = RoundState::Failed;
                    return Err(e.into());
                }
            }
        }
        let o_r = basis.decode(&or_res);

        // Protocol 5.14 step 5: commit to (x'_p, oᴿ_p) = (x', oᴿ) mod p.
        let ring_p = Ring::new(self.config.p.clone());
        let x_p = ring_p
            .from_uint(&self.x_prime)
            .to_uint()
            .to_be_bytes()
            .to_vec();
        let o_r_p = ring_p.from_uint(&o_r).to_uint().to_be_bytes().to_vec();
        let residues: ReceiverResidues = (x_p, o_r_p);
        let (opening, commitment) = residues.hash_commit();
        self.opening = Some(opening);

        self.o_r = Some(o_r);

        self.state = RoundState::Round3;
        Ok(Round2Recv {
            r: self.r.clone(),
            commitment,
            tau_seed: self.tau_seed,
        })
    }

    /// Runs round 3 and returns a message to send.
    pub fn round3(&mut self, x: F, msg: &Round2Send) -> Result<Round3Recv<F>, OleReceiverError> {
        self.check_state(RoundState::Round3)?;
        let basis = self.config.crt;
        let q = self.config.q;
        let ring_r = Ring::new(self.r.clone());

        let or = ring_r.from_uint(self.o_r.as_ref().expect("round2 must run first"));
        let x_prime = ring_r.from_uint(&self.x_prime);
        let os = ring_r.from_uint(&msg.os_mod_r);
        let a_prime = ring_r.from_uint(&msg.a_prime_mod_r);

        // Protocol 5.14 step 7 a,b.
        let lhs = &(&or + &os) - &(&a_prime * &x_prime);
        let f_q = if lhs == ring_r.zero() {
            F::zero()
        } else if lhs == ring_r.from_uint(basis.modulus()) {
            reduce_to_field::<F>(basis.modulus(), q)
        } else {
            self.state = RoundState::Failed;
            return Err(OleReceiverError::ConsistencyCheck);
        };
        self.f_q = Some(f_q);

        // Protocol 5.14 step 7 d, and step 7 c.
        let delta_x = x - self.x_prime_mod_q;
        let opening = self.opening.take().expect("round2 must run first");
        self.x = Some(x);
        self.state = RoundState::Finish;
        Ok(Round3Recv { delta_x, opening })
    }

    /// Finishes the protocol and returns the output.
    pub fn finish(self, msg: &Round3Send<F>) -> Result<F, OleReceiverError> {
        self.check_state(RoundState::Finish)?;
        let q = self.config.q;
        let o_r = self.o_r.expect("round2 must run first");
        let f_q = self.f_q.expect("round3 must run first");
        let x = self.x.expect("round3 must run first");
        Ok(reduce_to_field::<F>(&o_r, q) + msg.delta_b + msg.delta_a * x - f_q)
    }

    /// Errors with `OutOfOrder` unless the receiver is in `expected`.
    fn check_state(&self, expected: RoundState) -> Result<(), OleReceiverError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(OleReceiverError::OutOfOrder {
                expected: expected.name(),
                found: self.state.name(),
            })
        }
    }
}

/// Where an [`OleReceiver`] is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoundState {
    Initialized,
    Allocated,
    Round2,
    Round3,
    Finish,
    Failed,
}

impl RoundState {
    const fn name(self) -> &'static str {
        match self {
            RoundState::Initialized => "initialized",
            RoundState::Allocated => "allocated",
            RoundState::Round2 => "round2",
            RoundState::Round3 => "round3",
            RoundState::Finish => "finish",
            RoundState::Failed => "failed",
        }
    }
}

/// Error returned by an [`OleReceiver`] round.
// `Wmult` carries the internal `wmult::ReceiverError`, which is surfaced only
// opaquely (Display/source) — `wmult` is a crate-internal module, so the type
// is intentionally not nameable in the public API.
#[allow(private_interfaces)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OleReceiverError {
    /// A round was called in the wrong state: the method required state
    /// `expected`, but the receiver was at `found`.
    OutOfOrder {
        /// Name of the state the called round required.
        expected: &'static str,
        /// Name of the state the receiver was actually in.
        found: &'static str,
    },
    /// The sender's round-1 message could not be unpacked (wrong blob length
    /// for the CRT prime set).
    Pack(crate::dhim::PackError),
    /// A per-prime `Wmult` rejected the sender's response.
    Wmult(wmult::ReceiverError),
    /// The mod-`r` consistency check was neither `0` nor `n` — a malicious
    /// sender used an inconsistent `a'` or `oˢ`.
    ConsistencyCheck,
}

impl From<wmult::ReceiverError> for OleReceiverError {
    fn from(e: wmult::ReceiverError) -> Self {
        OleReceiverError::Wmult(e)
    }
}

impl From<crate::dhim::PackError> for OleReceiverError {
    fn from(e: crate::dhim::PackError) -> Self {
        OleReceiverError::Pack(e)
    }
}

impl std::fmt::Display for OleReceiverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OleReceiverError::OutOfOrder { expected, found } => write!(
                f,
                "OLE receiver called out of order: expected state `{expected}`, was at `{found}`"
            ),
            OleReceiverError::Pack(e) => write!(f, "OLE round-1 message malformed: {e}"),
            OleReceiverError::Wmult(e) => write!(f, "OLE Wmult failed: {e}"),
            OleReceiverError::ConsistencyCheck => write!(f, "OLE consistency check failed"),
        }
    }
}

impl std::error::Error for OleReceiverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OleReceiverError::Pack(e) => Some(e),
            OleReceiverError::Wmult(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::{
        OleSender,
        rot::{BlockToZpReceiver, BlockToZpSender},
        test_utils::{preflushed_ideal_rot, rots_per_ole},
    };
    use crypto_bigint::Resize;
    use mpz_fields::{UniformRand, p256::P256};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Runs an honest sender+receiver pair through flight 4, returning the
    /// receiver poised at `round3` together with the sender's genuine
    /// [`Round2Send`] opening and a receiver input `x`. The consistency check
    /// is the only receiver behaviour an honest end-to-end run can't reach,
    /// so we drive to its doorstep and let each test poke from there.
    fn drive_to_round3(seed: u64) -> (OleReceiver<P256>, Round2Send, P256) {
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
        let m4 = sender.round2(&m3).expect("sender round2");

        let x = P256::rand(&mut rrng);
        (receiver, m4, x)
    }

    /// A fresh receiver in the `Initialized` state plus an (unconsumed) ROT
    /// source, for exercising the state-machine guards in isolation.
    fn fresh_receiver(seed: u64) -> (OleReceiver<P256>, impl RotReceiverSource) {
        let cfg = crate::dhim::config::p256::config();
        let count = rots_per_ole(cfg);
        let (_s, r_inner) = preflushed_ideal_rot([seed as u8; 16], count);
        let rot = BlockToZpReceiver::new(r_inner);
        let mut rrng = ChaCha20Rng::seed_from_u64(seed);
        let receiver = OleReceiver::<P256>::new(cfg, &mut rrng);
        (receiver, rot)
    }

    /// A tampered flight-4 opening makes the mod-`r` discrepancy fall outside
    /// `{0, n}`, so `round3` aborts with `ConsistencyCheck` — and the failure
    /// poisons the receiver, so any later call is rejected as out-of-order.
    #[test]
    fn consistency_check_aborts_and_poisons() {
        let (mut receiver, m4, x) = drive_to_round3(7);

        // Bump oˢ mod r by 1: the integer discrepancy (oᴿ + oˢ) − a'·x' no longer
        // reduces to 0 or n mod r (negligibly unlikely to coincide for this r).
        let prec = m4.os_mod_r.bits_precision();
        let tampered = Round2Send {
            os_mod_r: m4.os_mod_r.wrapping_add(BoxedUint::from(1u64).resize(prec)),
            a_prime_mod_r: m4.a_prime_mod_r.clone(),
        };

        assert_eq!(
            receiver.round3(x, &tampered).unwrap_err(),
            OleReceiverError::ConsistencyCheck
        );
        assert_eq!(
            receiver.round3(x, &tampered).unwrap_err(),
            OleReceiverError::OutOfOrder {
                expected: "round3",
                found: "failed",
            }
        );
    }

    /// Runs an honest pair through flight 2, returning the receiver poised at
    /// `round2` and the sender's genuine [`Round1Send`].
    fn drive_to_round2(seed: u64) -> (OleReceiver<P256>, Round1Send) {
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
        (receiver, m2)
    }

    /// A round-1 corrections blob of the wrong length is rejected with
    /// `Pack(WrongLength)`, and the receiver is poisoned. (With flattened
    /// packing there is no per-prime structure left to corrupt — any tampering
    /// shows up as a single blob-length mismatch.)
    #[test]
    fn round2_rejects_wrong_correction_length() {
        let (mut receiver, m2) = drive_to_round2(31);
        let full = m2.corrections.len();
        let short = Round1Send {
            corrections: m2.corrections[..full - 1].to_vec(),
        };
        assert_eq!(
            receiver.round2(&short).unwrap_err(),
            OleReceiverError::Pack(crate::dhim::PackError::WrongLength {
                expected: full,
                found: full - 1,
            })
        );
        assert_eq!(
            receiver.round2(&short).unwrap_err(),
            OleReceiverError::OutOfOrder {
                expected: "round2",
                found: "failed",
            }
        );
    }

    /// `round1` requires `Allocated`; calling it straight after `new` is
    /// rejected.
    #[test]
    fn round1_before_alloc_is_out_of_order() {
        let (mut receiver, mut rot) = fresh_receiver(11);
        assert_eq!(
            receiver.round1(&mut rot).unwrap_err(),
            OleReceiverError::OutOfOrder {
                expected: "allocated",
                found: "initialized",
            }
        );
    }

    /// `round2` requires `Round2`; calling it before `round1` is rejected (the
    /// guard fires before the empty message is ever inspected).
    #[test]
    fn round2_before_round1_is_out_of_order() {
        let (mut receiver, _rot) = fresh_receiver(12);
        let empty = Round1Send {
            corrections: Vec::new(),
        };
        assert_eq!(
            receiver.round2(&empty).unwrap_err(),
            OleReceiverError::OutOfOrder {
                expected: "round2",
                found: "initialized",
            }
        );
    }

    /// `alloc` is a one-shot `Initialized → Allocated` transition; a second
    /// call is rejected.
    #[test]
    fn alloc_twice_is_out_of_order() {
        let (mut receiver, mut rot) = fresh_receiver(13);
        receiver.alloc(&mut rot).expect("first alloc succeeds");
        assert_eq!(
            receiver.alloc(&mut rot).unwrap_err(),
            OleReceiverError::OutOfOrder {
                expected: "initialized",
                found: "allocated",
            }
        );
    }
}
