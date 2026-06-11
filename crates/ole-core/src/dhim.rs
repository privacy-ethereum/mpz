//! Maliciously-secure, subquadratic-communication OLE
//! (Doerner–Haitner–Ishai–Makriyannis, [ePrint 2025/1722]).
//!
//! Realizes maliciously-secure OLE over a large prime field with *subquadratic*
//! communication: on sender input `(a, b) ∈ Z_q²` and receiver input `x ∈ Z_q`
//! it delivers `y = a·x + b mod q` to the receiver. The product is computed via
//! CRT decomposition over many small primes plus a per-prime Gilboa-style weak
//! multiplication (`wmult`), with a fresh-prime consistency check binding the
//! parties (Protocol 5.38 / `Π′`, secure under Conjecture 5.37).
//!
//! [ePrint 2025/1722]: https://eprint.iacr.org/2025/1722

// TODO(port): document public items and re-enable these crate-level lints for
// the dhim subtree. Relaxed for the initial integration pass.
#![allow(missing_docs, unreachable_pub, dead_code)]

use crypto_bigint::{BoxedUint, NonZero, Resize};
use hybrid_array::Array;
use itybity::{FromBitIterator, ToBits};
use mpz_core::{commit::Decommitment, hash::Hash};
use mpz_fields::Field;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub mod config;
pub mod rot;

pub(crate) mod crt;
pub(crate) mod ring;
pub(crate) mod rng;
pub(crate) mod sampler;
pub(crate) mod wmult;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

mod receiver;
mod sender;
pub use receiver::{OleReceiver, OleReceiverError};
pub use sender::{OleSender, OleSenderError};

/// Receiver message for round 1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Recv {
    /// Every prime's `Wmult` flip bits, concatenated and bit-packed in CRT
    /// order. The `ℓᵢ` boundaries are recovered from the public primes.
    pub(crate) flips: Vec<u8>,
}

impl Round1Recv {
    /// Flattens one [`wmult::ReceiverMsg`] per prime (in CRT order) into the
    /// packed wire form.
    pub(crate) fn pack(msgs: &[wmult::ReceiverMsg]) -> Self {
        Self {
            flips: Vec::<u8>::from_lsb0_iter(msgs.iter().flat_map(|m| m.flips.iter().copied())),
        }
    }

    /// Splits the packed flips back into per-prime [`wmult::ReceiverMsg`]s,
    /// using the widths `ℓᵢ = ⌈log₂ pᵢ⌉` from `crt`.
    pub(crate) fn unpack(
        &self,
        crt: &crt::CrtSystem,
    ) -> Result<Vec<wmult::ReceiverMsg>, PackError> {
        let widths: Vec<u32> = crt.primes().iter().map(|&p| wmult::ceil_log2(p)).collect();
        let total_bits: usize = widths.iter().map(|&l| l as usize).sum();
        let expected = total_bits.div_ceil(8);
        if self.flips.len() != expected {
            return Err(PackError::WrongLength {
                expected,
                found: self.flips.len(),
            });
        }
        let mut bits = self.flips.iter_lsb0();
        Ok(widths
            .iter()
            .map(|&l| wmult::ReceiverMsg {
                flips: bits.by_ref().take(l as usize).collect(),
            })
            .collect())
    }
}

/// Sender message for round 1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Send {
    /// Every prime's `Wmult` corrections, packed at `⌈log₂ pᵢ⌉` bits each in
    /// CRT order. Boundaries are recovered from the public primes.
    pub(crate) corrections: Vec<u8>,
}

impl Round1Send {
    /// Packs each prime's corrections at its own width `ℓᵢ = ⌈log₂ pᵢ⌉`,
    /// LSB-first.
    pub(crate) fn pack(msgs: &[wmult::SenderMsg], crt: &crt::CrtSystem) -> Self {
        let widths: Vec<u32> = crt.primes().iter().map(|&p| wmult::ceil_log2(p)).collect();
        let bits = msgs.iter().zip(&widths).flat_map(|(m, &l)| {
            // `itybity`'s `iter_lsb0` borrows its receiver and so can't be
            // returned from this `flat_map` over owned values; the low `ℓᵢ` bits of
            // each correction are taken with an explicit shift, and `itybity` packs
            // the resulting bools into bytes.
            m.corrections
                .iter()
                .flat_map(move |&o| (0..l).map(move |i| (o >> i) & 1 == 1))
        });
        Self {
            corrections: Vec::<u8>::from_lsb0_iter(bits),
        }
    }

    /// Splits the packed corrections back into per-prime [`wmult::SenderMsg`]s.
    pub(crate) fn unpack(&self, crt: &crt::CrtSystem) -> Result<Vec<wmult::SenderMsg>, PackError> {
        let widths: Vec<u32> = crt.primes().iter().map(|&p| wmult::ceil_log2(p)).collect();
        let total_bits: usize = widths.iter().map(|&l| (l * l) as usize).sum();
        let expected = total_bits.div_ceil(8);
        if self.corrections.len() != expected {
            return Err(PackError::WrongLength {
                expected,
                found: self.corrections.len(),
            });
        }
        let mut bits = self.corrections.iter_lsb0();
        let mut out = Vec::with_capacity(widths.len());
        for &l in &widths {
            let corrections = (0..l)
                .map(|_| u64::from_lsb0_iter(bits.by_ref().take(l as usize)))
                .collect();
            out.push(wmult::SenderMsg { corrections });
        }
        Ok(out)
    }
}

/// Error from unpacking a flattened round-1 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackError {
    /// The blob's byte length disagrees with the length implied by the primes.
    WrongLength {
        /// Bytes the prime set requires.
        expected: usize,
        /// Bytes the blob actually carried.
        found: usize,
    },
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackError::WrongLength { expected, found } => write!(
                f,
                "packed round-1 blob was {found} bytes, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for PackError {}

/// The receiver's `(x'_p, oᴿ_p) = (x', oᴿ) mod p` residues, big-endian bytes.
pub(crate) type ReceiverResidues = (Vec<u8>, Vec<u8>);

/// Receiver message for round 2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Recv {
    /// The sampled fresh prime `r`.
    pub(crate) r: BoxedUint,
    /// Commitment to [`ReceiverResidues`] `(x'_p, oᴿ_p)`.
    pub(crate) commitment: Hash,
    /// Master seed from which the sender derives each `Wmult`'s per-prime
    /// permutation `τ`.
    pub(crate) tau_seed: [u8; 16],
}

/// Sender message for round 2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Send {
    /// `oˢ mod r`.
    pub(crate) os_mod_r: BoxedUint,
    /// `a' mod r`.
    pub(crate) a_prime_mod_r: BoxedUint,
}

/// Receiver message for round 3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Recv<F> {
    /// `δ_x`.
    pub(crate) delta_x: F,
    /// Opening, revealing `(x'_p, oᴿ_p)`.
    pub(crate) opening: Decommitment<ReceiverResidues>,
}

/// Sender message for round 3.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Round3Send<F> {
    /// `δ_a = a − a' mod q`.
    pub(crate) delta_a: F,
    /// `δ_b = b + oˢ + a'·δ_x mod q`.
    pub(crate) delta_b: F,
}

/// Reduces a big integer `v` modulo the field modulus `q` and returns it as a
/// field element of `F`. Constant-time implementation.
///
/// # Panics
///
/// Panics if `q` is zero.
pub(crate) fn reduce_to_field<F: Field>(v: &BoxedUint, q: &BoxedUint) -> F {
    let precision = v.bits_precision().max(q.bits_precision());
    let q_nz = NonZero::new(q.clone().resize(precision))
        .into_option()
        .expect("q ≠ 0");
    // `rem_vartime` is variable-time *only* with respect to the divisor (`rhs`) —
    // for a fixed divisor it is constant-time (crypto-bigint's documented
    // contract). The divisor here is `q`, the fixed, publicly-known field modulus,
    // so this reduction runs in time independent of the secret dividend `v`.
    let reduced = v.clone().resize(precision).rem_vartime(&q_nz); // < q

    let le = reduced.to_le_bytes();
    let arr = Array::<u8, F::ByteSize>::try_from(&le[..F::BYTE_SIZE])
        .expect("reduced < q fits in F::BYTE_SIZE bytes");
    F::try_from(arr).expect("a value < q is a canonical field element")
}

/// Samples a uniform integer in `[0, 2^nbits)` at the given precision.
pub(crate) fn random_bits<R: Rng + ?Sized>(rng: &mut R, nbits: u32, precision: u32) -> BoxedUint {
    let nbytes = nbits.div_ceil(8) as usize;
    let mut bytes = vec![0u8; nbytes];
    rng.fill_bytes(&mut bytes);
    // Clear the bits above `nbits` in the top byte.
    let rem = nbits % 8;
    if rem != 0 {
        bytes[nbytes - 1] &= (1u8 << rem) - 1;
    }
    BoxedUint::from_le_slice(&bytes, precision).expect("fits in `precision` bits")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::{
        config::Config,
        rot::{BlockToZpReceiver, BlockToZpSender},
        test_utils::{preflushed_ideal_rot, rots_per_ole},
    };
    use mpz_core::Block;
    use mpz_fields::{UniformRand, p256::P256};
    use mpz_ot_core::rot::{ROTReceiver, ROTSender};
    use rand::{CryptoRng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    /// Drives one full OLE `Π′` execution locally by shuttling the typed
    /// messages between an [`OleSender`] and an [`OleReceiver`] (no I/O).
    /// Returns the receiver's output `y` (or an abort).
    #[allow(clippy::too_many_arguments)]
    pub fn run_ole_local<F, SOt, ROt, SRng, RRng>(
        config: &'static Config,
        sender_ot: SOt,
        receiver_ot: ROt,
        sender_rng: &mut SRng,
        receiver_rng: &mut RRng,
        a: F,
        b: F,
        x: F,
    ) -> Result<F, OleError>
    where
        F: Field,
        SOt: ROTSender<[Block; 2]>,
        ROt: ROTReceiver<bool, Block>,
        SRng: Rng + ?Sized,
        RRng: CryptoRng + ?Sized,
    {
        let mut sender_rot = BlockToZpSender::new(sender_ot);
        let mut receiver_rot = BlockToZpReceiver::new(receiver_ot);

        let mut sender = OleSender::new(config, sender_rng);
        let mut receiver = OleReceiver::new(config, receiver_rng);

        sender.alloc(&mut sender_rot)?;
        receiver.alloc(&mut receiver_rot)?;

        let m1 = receiver.round1(&mut receiver_rot)?;
        let m2 = sender.round1(&mut sender_rot, &m1)?;
        let m3 = receiver.round2(&m2)?;
        let m4 = sender.round2(&m3)?;
        let m5 = receiver.round3(x, &m4)?;
        let m6 = sender.round3(a, b, &m5)?;
        Ok(receiver.finish(&m6)?)
    }

    /// `reduce_to_field::<P256>` reduces `q ≡ 0` and round-trips field
    /// elements, including the wrap `e + q ≡ e`.
    #[test]
    fn reduce_to_field_is_correct() {
        let q = crate::dhim::config::p256::config().q;
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let prec = 1600;

        // q ≡ 0 (mod q): validates the config modulus equals the real P-256 q.
        assert_eq!(
            reduce_to_field::<P256>(&q.clone().resize(prec), q),
            P256::zero()
        );

        for _ in 0..50 {
            let e: P256 = P256::rand(&mut rng);
            // Embed e as a big integer (P256 serializes little-endian).
            let e_le: [u8; 32] = e.into();
            let mut e_be = [0u8; 32];
            for i in 0..32 {
                e_be[i] = e_le[31 - i];
            }
            let e_boxed = BoxedUint::from_be_slice(&e_be, 256).unwrap().resize(prec);

            // e < q reduces to itself, and e + q reduces back to e.
            assert_eq!(reduce_to_field::<P256>(&e_boxed, q), e);
            let e_plus_q = e_boxed.wrapping_add(q.clone().resize(prec));
            assert_eq!(reduce_to_field::<P256>(&e_plus_q, q), e);
        }
    }

    /// `random_bits` stays within `[0, 2^nbits)`, sits at the requested
    /// precision, and (over many draws) does reach its top bit — so it isn't
    /// trivially small.
    #[test]
    fn random_bits_respects_bound() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        for &nbits in &[1u32, 7, 8, 9, 143, 256] {
            let precision = 512;
            let mut top_bit_seen = false;
            for _ in 0..200 {
                let v = random_bits(&mut rng, nbits, precision);
                assert!(v.bits() <= nbits, "nbits={nbits}: got {} bits", v.bits());
                assert_eq!(v.bits_precision(), precision);
                top_bit_seen |= v.bits() == nbits;
            }
            assert!(
                top_bit_seen,
                "nbits={nbits}: top bit never set in 200 draws"
            );
        }
    }

    /// Honest end-to-end `Π′`: `y = a·x + b` over `Z_q` for random inputs.
    #[test]
    fn honest_ole_outputs_ax_plus_b() {
        let cfg = crate::dhim::config::p256::config();
        let mut input_rng = ChaCha20Rng::seed_from_u64(123);

        for k in 0..8u64 {
            let (send, recv) = preflushed_ideal_rot([k as u8; 16], rots_per_ole(cfg));
            let mut srng = ChaCha20Rng::seed_from_u64(1000 + k);
            let mut rrng = ChaCha20Rng::seed_from_u64(2000 + k);

            let a = P256::rand(&mut input_rng);
            let b = P256::rand(&mut input_rng);
            let x = P256::rand(&mut input_rng);

            let y = run_ole_local(cfg, send, recv, &mut srng, &mut rrng, a, b, x)
                .expect("honest execution must not abort");

            assert_eq!(y, a * x + b, "iteration {k}");
        }
    }

    /// `pack`/`unpack` round-trip the per-prime `Wmult` messages exactly, and
    /// the packed blobs are the bit-exact ideal size (`⌈Σℓᵢ / 8⌉` for flips,
    /// `⌈Σℓᵢ² / 8⌉` for corrections).
    #[test]
    fn round1_messages_round_trip_packed() {
        let crt = crate::dhim::config::p256::config().crt;
        let l = |p: u64| crate::dhim::wmult::ceil_log2(p) as usize;

        let recv: Vec<wmult::ReceiverMsg> = crt
            .primes()
            .iter()
            .map(|&p| wmult::ReceiverMsg {
                flips: (0..l(p)).map(|i| i % 3 == 0).collect(),
            })
            .collect();
        let send: Vec<wmult::SenderMsg> = crt
            .primes()
            .iter()
            .map(|&p| wmult::SenderMsg {
                corrections: (0..l(p)).map(|i| (i as u64 * 7) % p).collect(),
            })
            .collect();

        let r1r = Round1Recv::pack(&recv);
        let r1s = Round1Send::pack(&send, crt);

        let lsum: usize = crt.primes().iter().map(|&p| l(p)).sum();
        let l2sum: usize = crt.primes().iter().map(|&p| l(p) * l(p)).sum();
        assert_eq!(r1r.flips.len(), lsum.div_ceil(8), "flips packed size");
        assert_eq!(
            r1s.corrections.len(),
            l2sum.div_ceil(8),
            "corrections packed size"
        );

        assert_eq!(r1r.unpack(crt).unwrap(), recv, "flips round-trip");
        assert_eq!(r1s.unpack(crt).unwrap(), send, "corrections round-trip");
    }

    /// Error from a local OLE `Π′` run ([`run_ole_local`]): either party can
    /// fail. In a real deployment each side only ever sees its own
    /// [`OleSenderError`] / [`OleReceiverError`]; this driver-level enum
    /// unifies the two so one function can shuttle both parties.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum OleError {
        /// The sender failed (only ever out-of-order — it runs no abortable
        /// check).
        Sender(OleSenderError),
        /// The receiver failed (consistency-check abort or out-of-order).
        Receiver(OleReceiverError),
    }

    impl From<OleSenderError> for OleError {
        fn from(e: OleSenderError) -> Self {
            OleError::Sender(e)
        }
    }

    impl From<OleReceiverError> for OleError {
        fn from(e: OleReceiverError) -> Self {
            OleError::Receiver(e)
        }
    }

    impl std::fmt::Display for OleError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                OleError::Sender(e) => write!(f, "{e}"),
                OleError::Receiver(e) => write!(f, "{e}"),
            }
        }
    }

    impl std::error::Error for OleError {}
}
