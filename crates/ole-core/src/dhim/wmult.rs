//! Weak multiplication over a single prime `p` (Protocol 5.11).
//!
//! `Wmult_p` (Functionality 5.10) is a weak OLE over `Z_p`: on sender input
//! `a` and receiver input `x` it produces an additive sharing of the product:
//!
//! z_S + z_R ≡ a · x   (mod p),
//!
//! with `z_S` held by the sender and `z_R` by the receiver.

use mpz_core::prg::Prg;
use rand::Rng;
use serde::{Deserialize, Serialize};

mod cot;
mod receiver;
mod sender;
mod zp;

pub(crate) use receiver::{Receiver, ReceiverError};
pub(crate) use sender::{Sender, SenderError};

/// A bit permutation `τ` for one `Wmult` (`ℓ = ⌈log₂ p⌉` entries).
///
/// `τ` maps a **processing slot** `i ∈ {0,…,ℓ−1}` — the i-th COT consumed, in
/// order — to the **bit position** `τ(i) ∈ {0,…,ℓ−1}` of the value that slot
/// handles: slot `i` reads bit `τ(i)` of its input and contributes weight
/// `2^{τ(i)}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tau(Vec<usize>);

impl Tau {
    /// Samples a permutation of `{0,…,ℓ−1}` from `rng` — an unbiased
    /// Fisher–Yates.
    fn from_rng<R: Rng + ?Sized>(rng: &mut R, l: usize) -> Self {
        use rand::seq::SliceRandom;
        let mut tau: Vec<usize> = (0..l).collect();
        tau.shuffle(rng);
        Tau(tau)
    }

    /// ℓ — the number of slots / bit positions.
    fn len(&self) -> usize {
        self.0.len()
    }

    /// The bit position `τ(i)` handled by slot `i`.
    fn bit_position(&self, slot: usize) -> usize {
        self.0[slot]
    }

    /// The weight slot `i` contributes: `2^{τ(i)} mod p`.
    fn weight(&self, slot: usize) -> u64 {
        //Already `< p`, since `τ(i) ≤ ℓ−1` and `2^{ℓ−1} < p`.
        1u64 << self.bit_position(slot)
    }

    /// The bits of `value` reordered into processing-slot order: entry `i` is
    /// bit `τ(i)` of `value` (`value` must fit in `ℓ` bits).
    fn permuted_bits(&self, value: u64) -> Vec<bool> {
        (0..self.len())
            .map(|i| (value >> self.bit_position(i)) & 1 == 1)
            .collect()
    }
}

/// The receiver → sender message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiverMsg {
    /// COT flip bit `fᵢ = λᵢ ⊕ iᵢ` for each of the `ℓ` positions.
    pub(crate) flips: Vec<bool>,
}

/// The sender → receiver message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SenderMsg {
    /// `oᵢ = a₁ − a₀ − a mod p` for each of the `ℓ` positions.
    pub(crate) corrections: Vec<u64>,
}

/// `⌈log₂ p⌉` for `p ≥ 2` — the number of bit positions / OTs a single `Wmult`
/// over `p` consumes (and the count each side reserves in `alloc`). It is also
/// the per-prime field width the round-1 packing uses: `ℓᵢ` flip bits, and
/// `ℓᵢ` corrections of `ℓᵢ` bits each.
pub(crate) fn ceil_log2(p: u64) -> u32 {
    debug_assert!(p >= 2);
    u64::BITS - (p - 1).leading_zeros()
}

/// Derives the per-prime permutations `(τ₁,…,τ_t)` for one OLE from a single
/// `master` seed.
///
/// # Why `τ` is owned by the layer above, not by each [`Receiver`]
///
/// In Protocol 5.11 `τ` is the *receiver's* randomness, sent to the sender in
/// step 3 — so the natural encapsulation would have each [`Receiver`] sample
/// and emit its own `τ`. We deliberately don't: the receiver chooses one
/// 16-byte master seed, both parties expand it here into all `t` permutations,
/// and only that seed travels the wire. Sending `t` independent permutations
/// instead would cost ~0.9–2.5 KB against a ~1.77 KB total for `|q| = 256`.
pub(crate) fn derive_taus(master: [u8; 16], primes: &[u64]) -> Vec<Tau> {
    let mut prg = Prg::new_with_seed(master);
    primes
        .iter()
        .map(|&p| Tau::from_rng(&mut prg, ceil_log2(p) as usize))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::test_utils::ideal_rot_pair;
    use mpz_core::prg::Prg;

    /// Runs one full Wmult over `p` with inputs `(a, x)` and returns
    /// `(z_S, z_R)`.
    fn run(seed: [u8; 16], rseed: [u8; 16], a: u64, x: u64, p: u64) -> (u64, u64) {
        let (mut send, mut recv) = ideal_rot_pair(seed);
        let mut rng = Prg::new_with_seed(rseed);
        // Both parties derive the same τ from a shared master seed.
        let tau = derive_taus([0x5Au8; 16], &[p]).remove(0);

        let mut receiver = Receiver::new(x, p, tau.clone());
        receiver.alloc(&mut recv).expect("receiver alloc");
        let rmsg = receiver.request(&mut recv, &mut rng).expect("request");
        let mut sender = Sender::new(a, p);
        sender.alloc(&mut send).expect("sender alloc");
        let smsg = sender.respond(&mut send, &rmsg).expect("ℓ flips");
        // τ reaches the sender only after its corrections are fixed.
        let z_s = sender.output(&tau).expect("output");
        let z_r = receiver.finish(&smsg).expect("ℓ corrections");
        (z_s, z_r)
    }

    /// The defining relation: `z_S + z_R ≡ a·x (mod p)` for all inputs.
    #[test]
    fn wmult_relation_holds() {
        for &p in &[5u64, 7, 13, 97, 1009, 1063] {
            for a in (0..p).step_by(((p / 23) + 1) as usize) {
                for x in 0..p {
                    let (z_s, z_r) = run([11u8; 16], [22u8; 16], a, x, p);
                    assert_eq!((z_s + z_r) % p, (a * x) % p, "p={p} a={a} x={x}");
                }
            }
        }
    }

    /// Correctness must be independent of the receiver's randomness (`c`, `τ`).
    #[test]
    fn relation_independent_of_receiver_randomness() {
        let p = 1063;
        let (a, x) = (777, 432);
        for s in 0u8..20 {
            let (z_s, z_r) = run([s; 16], [s.wrapping_add(100); 16], a, x, p);
            assert_eq!((z_s + z_r) % p, (a * x) % p);
        }
    }

    /// `Tau::from_rng` yields a genuine permutation of `{0,…,ℓ−1}`, and a PRG
    /// re-keyed from the same seed reproduces the same `τ` (both parties derive
    /// the same permutation).
    #[test]
    fn from_rng_is_a_permutation() {
        let p = 1063;
        let l = ceil_log2(p) as usize;
        let identity = (0..l).collect::<Vec<_>>();

        for s in 0u8..50 {
            let tau = Tau::from_rng(&mut Prg::new_with_seed([s; 16]), l);
            let again = Tau::from_rng(&mut Prg::new_with_seed([s; 16]), l);
            assert_eq!(tau, again, "deterministic in seed");
            let mut seen: Vec<usize> = (0..l).map(|i| tau.bit_position(i)).collect();
            seen.sort_unstable();
            assert_eq!(seen, identity);
        }
    }

    /// `Tau::permuted_bits` reorders the low ℓ bits of `value` by `τ`: output
    /// slot `i` carries bit `τ(i)`. Checked independently of `τ` by a popcount
    /// invariant, and as a lossless bijection by scattering each output bit
    /// back to its source position `τ(i)` — which must recover `value`.
    #[test]
    fn permuted_bits_reorders_by_tau() {
        let l = ceil_log2(1063) as usize; // ℓ for the largest CRT prime (11 bits)
        let mask = (1u64 << l) - 1;
        for s in 0u8..32 {
            let tau = Tau::from_rng(&mut Prg::new_with_seed([s; 16]), l);
            for value in [0, 1, 0b1010_0101, mask, (s as u64 * 37) & mask] {
                let bits = tau.permuted_bits(value);
                assert_eq!(bits.len(), l);

                // τ only moves bits, so the set-bit count is preserved.
                assert_eq!(
                    bits.iter().filter(|&&b| b).count() as u32,
                    value.count_ones()
                );

                // Scatter output bit `i` back to position `τ(i)` ⇒ recover `value`.
                let recovered: u64 = bits
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| (b as u64) << tau.bit_position(i))
                    .sum();
                assert_eq!(recovered, value, "s={s} value={value:#b}");
            }
        }
    }

    /// `ceil_log2(p)` is the smallest `ℓ` with `2^ℓ ≥ p` — i.e. `ℓ` COTs cover
    /// every residue `< p`.
    #[test]
    fn ceil_log2_matches_reference() {
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(1063), 11); // largest CRT prime
        for p in 2u64..4000 {
            let l = ceil_log2(p);
            assert!(1u64 << l >= p, "2^{l} < {p}");
            assert!(1u64 << (l - 1) < p, "{p} ≤ 2^{} — not minimal", l - 1);
        }
    }
}
