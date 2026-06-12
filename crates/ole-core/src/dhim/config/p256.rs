//! Precomputed configuration for the **P-256 base field**.

use std::sync::LazyLock;

use crypto_bigint::BoxedUint;

use crate::dhim::crt::CrtSystem;

use super::{Config, Params};

/// CRT primes for the P-256 config (`|q| = 256`, `κ_s = 40`): the precise
/// minimal set of primes `> 3` with `∏ pᵢ ≥ 2^(κ_s+3+|s_a|+|s_x|) = 2^1453`.
///
/// **NOT** over-provisioned — the first-177-primes default overshoots by ~30
/// bits / ~3 primes.
pub const P256_PRIMES: &[u64] = &[
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
    103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
    199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
    313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
    433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
    563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
    673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
    941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
];

/// The parameter set; the matching row of Table 5.16.
pub const P256_KAPPA_S40: Params = Params {
    q_bits: 256,
    kappa_s: 40,
    s_r_bits: 143,
    s_a_bits: 537,
    s_x_bits: 873,
    n_bits: 1460,
};

/// The CRT system.
static P256_CRT: LazyLock<CrtSystem> = LazyLock::new(|| CrtSystem::new(P256_PRIMES.to_vec()));

/// The P-256 base field modulus `q = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1`, big-endian.
const P256_MODULUS_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// The P-256 field modulus `q` as a [`BoxedUint`], cached for the process.
static P256_Q: LazyLock<BoxedUint> =
    LazyLock::new(|| BoxedUint::from_be_slice(&P256_MODULUS_BE, 256).expect("32 bytes ⇒ 256-bit"));

/// The receiver-consistency prime `p` (Protocol 5.14 step 8a): the smallest
/// prime `≥ 2^(κ_s+3) = 2^43`, i.e. `2^43 + 29`. Being a ~44-bit prime it is
/// automatically coprime to `q` (256-bit) and the CRT primes (`≤ 1049`).
///
/// `p ≥ 2^(κ_s+3)` is Theorem 5.17's binding bound, and it is sufficient: the
/// one extra bit over the malicious-receiver bound of the simpler Protocol 4.10
/// (`p ≥ 2^(κ_s+2)`) is exactly the "slight increment" Claim 5.19 needs for the
/// two values `{0, n} mod p` that pass the step-8a test. So the smallest such
/// prime is the minimal valid choice — nothing finer to pin down.
const P256_P_VALUE: u64 = 8_796_093_022_237;
static P256_P: LazyLock<BoxedUint> = LazyLock::new(|| BoxedUint::from(P256_P_VALUE));

/// The assembled P-256 config.
static P256_CONFIG: LazyLock<Config> = LazyLock::new(|| Config {
    params: P256_KAPPA_S40,
    crt: &P256_CRT,
    q: &P256_Q,
    p: &P256_P,
});

/// The config for the **P-256 base field**.
pub fn config() -> &'static Config {
    &P256_CONFIG
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::ConcatenatingMul;

    /// Trial-division primality for the small candidates the search enumerates.
    fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        if n.is_multiple_of(2) {
            return n == 2;
        }
        let mut d = 3u64;
        while d * d <= n {
            if n.is_multiple_of(d) {
                return false;
            }
            d += 2;
        }
        true
    }

    /// The minimal prefix of primes `> 3` whose product has more than
    /// `bound_bits` bits — i.e. `∏ pᵢ ≥ 2^bound_bits`. This is the offline
    /// derivation that produced [`P256_PRIMES`]; kept here as executable
    /// documentation and the verifier below.
    fn precise_primes(bound_bits: u32) -> Vec<u64> {
        let mut primes = Vec::new();
        let mut product = BoxedUint::from(1u64);
        let mut candidate = 5u64;
        loop {
            if is_prime(candidate) {
                primes.push(candidate);
                // `concatenating_mul` widens, so the exact product is preserved.
                product = product.concatenating_mul(&BoxedUint::from(candidate));
                if product.bits() > bound_bits {
                    break;
                }
            }
            candidate += 2;
        }
        primes
    }

    /// The hard-coded [`P256_PRIMES`] is *exactly* the precise minimal CRT
    /// prime set the binding constraint `n ≥ 2^(κ_s+3)·s_a·s_x` demands —
    /// recomputed here from the [`Params`](crate::dhim::config::Params) row
    /// and cross-checked, so the constant and the parameters cannot
    /// silently drift apart.
    #[test]
    fn p256_primes_match_precise_derivation() {
        let p = P256_KAPPA_S40;
        let bound_bits = p.kappa_s + 3 + p.s_a_bits + p.s_x_bits;
        assert_eq!(precise_primes(bound_bits).as_slice(), P256_PRIMES);
    }

    /// The baked prime set is precise: it clears the binding constraint, is
    /// minimal (dropping its largest prime falls short), and is trimmed below
    /// the old first-177 default.
    #[test]
    fn p256_basis_is_precise_and_minimal() {
        let cfg = config();
        assert_eq!(cfg.crt.num_primes(), P256_PRIMES.len());
        assert!(
            cfg.crt.num_primes() < 177,
            "expected fewer than the over-provisioned 177, got {}",
            cfg.crt.num_primes()
        );

        // Binding constraint: n ≥ 2^bound ⟺ |n| > bound.
        let bound = cfg.params.kappa_s + 3 + cfg.params.s_a_bits + cfg.params.s_x_bits;
        assert!(
            cfg.crt.modulus().bits() > bound,
            "n ({} bits) must clear the binding bound 2^{bound}",
            cfg.crt.modulus().bits()
        );

        // Minimality: the prefix without its largest prime must fall short.
        let one_short = CrtSystem::new(P256_PRIMES[..P256_PRIMES.len() - 1].to_vec());
        assert!(
            one_short.modulus().bits() <= bound,
            "prime set is not minimal: {} primes already suffice",
            P256_PRIMES.len() - 1
        );
    }
}
