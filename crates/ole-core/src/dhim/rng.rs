//! RNG version bridge.
//!
//! mpz rides `rand_core` 0.9, but the `crypto-bigint` / `crypto-primes` 0.7
//! line moved to `rand_core` 0.10 — so their RNG traits are distinct types and
//! an mpz RNG can't be handed to `random_prime` / `random_mod_vartime`
//! directly.
//!
//! In `rand_core` 0.10 the core trait is the fallible [`TryRng`], with
//! `Rng: TryRng<Error = Infallible>` and `CryptoRng: Rng + TryCryptoRng` both
//! blanket-implemented. [`Compat`] implements `TryRng`/`TryCryptoRng` over a
//! `rand_core` 0.9 RNG (whose methods are infallible), so it picks up `Rng` and
//! `CryptoRng` automatically.

use core::convert::Infallible;

use crypto_bigint::rand_core::{TryCryptoRng, TryRng};

/// Wraps a `rand_core` 0.9 RNG `R` so it satisfies crypto-bigint's `rand_core`
/// 0.10 `Rng`/`CryptoRng` bounds.
pub(crate) struct Compat<R: ?Sized>(pub(crate) R);

impl<R: rand::RngCore + ?Sized> TryRng for Compat<R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R: rand::CryptoRng + ?Sized> TryCryptoRng for Compat<R> {}
