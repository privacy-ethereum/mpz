//! Random-prime sampler.

use crate::dhim::rng::Compat;
use crypto_bigint::BoxedUint;
use crypto_primes::{Flavor, random_prime};
use rand::{CryptoRng, RngCore};

/// Samples a uniformly random `bit_length`-bit prime `r`, excluding `q`.
///
/// # Panics
///
/// Panics if `bit_length` is too small to admit a prime
/// with the top bit set.
pub fn sample_random_prime<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
    bit_length: u32,
    q: &BoxedUint,
) -> BoxedUint {
    let mut rng = Compat(rng);
    loop {
        let r: BoxedUint = random_prime(&mut rng, Flavor::Any, bit_length);
        // `BoxedUint`'s `==` is value-based even across differing precisions,
        // so `r` and `q` can be compared directly — no need to resize either to
        // a common precision first.
        if r != *q {
            return r;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::crt::CrtSystem;
    use crypto_bigint::{NonZero, Resize};
    use crypto_primes::is_prime as cp_is_prime;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Miller–Rabin primality test for a [`BoxedUint`] (delegates to
    /// `crypto-primes`).
    pub fn is_prime(candidate: &BoxedUint) -> bool {
        cp_is_prime(Flavor::Any, candidate)
    }

    #[test]
    fn samples_exact_bit_length_primes() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let q = BoxedUint::from(0u64); // never matches a prime
        for _ in 0..10 {
            let r = sample_random_prime(&mut rng, 143, &q);
            assert_eq!(r.bits(), 143, "MSB set ⇒ exactly 143 bits");
            assert!(is_prime(&r));
        }
    }

    #[test]
    fn coprime_to_smooth_modulus() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let basis = CrtSystem::new(crate::dhim::config::p256::P256_PRIMES.to_vec());
        let q = BoxedUint::from(0u64);

        let r = sample_random_prime(&mut rng, 143, &q);

        // r ∤ n (r is far larger than any prime factor of n), so gcd(r, n) = 1.
        let r_wide = r.clone().resize(basis.precision());
        let r_nz = NonZero::new(r_wide).into_option().unwrap();
        let n_mod_r = basis.modulus().rem_vartime(&r_nz);
        assert!(!bool::from(n_mod_r.is_zero()));
    }

    #[test]
    fn excludes_q() {
        // Sample once, then re-sample with the same seed while excluding the
        // first result: the exclusion must force a different prime.
        let r1 = sample_random_prime(
            &mut ChaCha20Rng::seed_from_u64(9),
            32,
            &BoxedUint::from(0u64),
        );
        let r2 = sample_random_prime(&mut ChaCha20Rng::seed_from_u64(9), 32, &r1);

        assert!(is_prime(&r1) && is_prime(&r2));
        assert_ne!(r1, r2, "the excluded prime must not be returned");
    }

    /// `BoxedUint`'s `==` is value-based across differing precisions — the
    /// property `sample_random_prime`'s `q` exclusion relies on.
    #[test]
    fn boxed_uint_equality_is_value_based() {
        let five_small = BoxedUint::from(5u64); // 64-bit precision
        let five_wide = BoxedUint::from(5u64).resize(512);
        let seven = BoxedUint::from(7u64);
        assert_eq!(five_small, five_wide);
        assert_ne!(five_small, seven);
    }
}
