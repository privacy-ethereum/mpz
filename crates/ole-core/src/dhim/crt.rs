//! CRT system.

use crypto_bigint::{BoxedUint, ConcatenatingMul, Limb, NonZero, Reciprocal, Resize};

/// The CRT system for a fixed set of small primes.
#[derive(Clone)]
pub(crate) struct CrtSystem {
    /// The CRT moduli `pᵢ`, distinct primes `> 3`, in increasing order.
    primes: Vec<u64>,
    /// The smooth modulus `n = ∏ pᵢ`.
    modulus: BoxedUint,
    /// `n` as a non-zero divisor, for the modular ops in [`Self::decode`].
    modulus_nz: NonZero<BoxedUint>,
    /// Cofactors `Mᵢ = n / pᵢ`.
    cofactors: Vec<BoxedUint>,
    /// Inverses `Mᵢ⁻¹ mod pᵢ` (`Mᵢ` reduced mod `pᵢ` first, then inverted).
    inverses: Vec<u64>,
    /// Precomputed Barrett reciprocals for single-limb reduction mod each `pᵢ`
    /// used by [`Self::encode`].
    reciprocals: Vec<Reciprocal>,
    /// Shared bit precision of every [`BoxedUint`] in this basis.
    precision: u32,
}

impl CrtSystem {
    /// Builds a system from an explicit list of distinct primes `> 3`.
    ///
    /// # Panics
    ///
    /// Panics if `primes` is empty.
    pub(crate) fn new(primes: Vec<u64>) -> Self {
        assert!(!primes.is_empty(), "CRT basis needs at least one prime");

        // n = ∏ pᵢ. The running precision grows with each factor; we normalise once at
        // the end.
        let mut product = BoxedUint::from(1u64);
        for &p in &primes {
            product = product.concatenating_mul(&BoxedUint::from(p));
        }
        // Working precision. `decode` sums Σᵢ Mᵢ·tᵢ (each term < n, t terms) into one
        // wide integer and reduces only once at the end, so the accumulator can
        // reach up to t·n − 1 < 2^(|n| + ⌈log₂ t⌉). That worst case is a closed
        // form in public data known right here — the prime set alone, never the
        // secret residues — so we size the precision to it exactly: |n| + ⌈log₂
        // t⌉ + 1 bits (the +1 keeps the bound strict), rounded up to a multiple
        // of 64 so the width is identical on 64-bit and wasm32 (32-bit limb)
        // targets.
        let acc_bits = product.bits() + ceil_log2(primes.len() as u32); // ⌈log₂(t·n)⌉
        let precision = (acc_bits + 1).next_multiple_of(64);

        // Holds by construction; guards a future prime-set or `decode` change from
        // silently overflowing the accumulator's `wrapping_add`.
        debug_assert!(
            precision > acc_bits,
            "decode accumulator (< t·n, {acc_bits} bits) must fit precision ({precision} bits)"
        );

        let modulus = at_precision(product, precision);
        let modulus_nz = NonZero::new(modulus.clone())
            .into_option()
            .expect("n = ∏ pᵢ is non-zero");

        let mut cofactors = Vec::with_capacity(primes.len());
        let mut inverses = Vec::with_capacity(primes.len());
        let mut reciprocals = Vec::with_capacity(primes.len());
        for &p in &primes {
            let recip = Reciprocal::new(NonZero::<Limb>::new_unwrap(Limb::from_u64(p)));
            // Mᵢ = n / pᵢ (exact: pᵢ | n).
            let p_nz = nz_prime_at(p, precision);
            let (cofactor, remainder) = modulus.div_rem(&p_nz);
            debug_assert!(bool::from(remainder.is_zero()), "pᵢ must divide n");
            // (Mᵢ mod pᵢ)⁻¹ mod pᵢ.
            let cofactor_mod_p = cofactor.rem_limb_with_reciprocal(&recip).0;
            inverses.push(inv_mod_u64(cofactor_mod_p, p));
            cofactors.push(cofactor);
            reciprocals.push(recip);
        }

        Self {
            primes,
            modulus,
            modulus_nz,
            cofactors,
            inverses,
            reciprocals,
            precision,
        }
    }

    /// The CRT moduli `pᵢ`.
    pub(crate) fn primes(&self) -> &[u64] {
        &self.primes
    }

    /// The number of primes `t`.
    #[cfg(test)]
    pub(crate) fn num_primes(&self) -> usize {
        self.primes.len()
    }

    /// The smooth modulus `n = ∏ pᵢ`.
    pub(crate) fn modulus(&self) -> &BoxedUint {
        &self.modulus
    }

    /// The smooth modulus as a non-zero divisor.
    #[cfg(test)]
    pub(crate) fn modulus_nz(&self) -> &NonZero<BoxedUint> {
        &self.modulus_nz
    }

    /// The shared bit precision of the basis's [`BoxedUint`]s.
    pub(crate) fn precision(&self) -> u32 {
        self.precision
    }

    /// Maps `x` to its residue vector `(x mod p₁, …, x mod p_t)`.
    ///
    /// `x` may be given at any precision; it is reduced modulo each `pᵢ`
    /// independently, so values `≥ n` are handled the same as `x mod n`.
    pub(crate) fn encode(&self, x: &BoxedUint) -> Vec<u64> {
        self.reciprocals
            .iter()
            .map(|recip| x.rem_limb_with_reciprocal(recip).0)
            .collect()
    }

    /// Reconstructs the unique `x ∈ Z_n` with `x ≡ residues[i] (mod pᵢ)`.
    ///
    /// Each `residues[i]` is reduced mod `pᵢ` first, so out-of-range inputs are
    /// tolerated.
    ///
    /// # Panics
    ///
    /// Panics if `residues.len() != self.num_primes()`.
    pub(crate) fn decode(&self, residues: &[u64]) -> BoxedUint {
        assert_eq!(
            residues.len(),
            self.primes.len(),
            "residue count must match the number of primes"
        );

        // Accumulate Σᵢ tᵢ·Mᵢ in one wide integer without reducing: each
        // tᵢ·Mᵢ < n and the sum of t terms is < t·n. The basis precision is
        // sized to exactly this bound (|n| + ⌈log₂ t⌉ + 1 bits; see `new`), so
        // the accumulator never overflows. A single reduction by n at the end
        // replaces the t per-term modular multiplications.
        let mut acc = BoxedUint::zero_with_precision(self.precision);
        for (((&p, &res), &inv), cof) in self
            .primes
            .iter()
            .zip(residues)
            .zip(&self.inverses)
            .zip(&self.cofactors)
        {
            // tᵢ = rᵢ · (Mᵢ⁻¹ mod pᵢ)  mod pᵢ  — a single u64 < pᵢ.
            let ti = mulmod_u64(res % p, inv, p);
            if ti == 0 {
                continue;
            }
            // term = Mᵢ · tᵢ  (exact: < n; a cheap single-limb multiply).
            let term = cof * &BoxedUint::from(ti);
            acc = acc.wrapping_add(&term);
        }
        acc.rem_vartime(&self.modulus_nz)
    }
}

/// `⌈log₂ n⌉` for `n ≥ 1` — the smallest `k` with `2^k ≥ n`, i.e. the bit width
/// needed so any value `< n` fits. `ceil_log2(1) = 0`.
fn ceil_log2(n: u32) -> u32 {
    debug_assert!(n >= 1, "ceil_log2 is defined for n ≥ 1");
    u32::BITS - (n - 1).leading_zeros()
}

/// Normalises `v` to exactly `precision` bits (widening or shortening as
/// needed). The value must fit in `precision` bits.
fn at_precision(v: BoxedUint, precision: u32) -> BoxedUint {
    v.resize(precision)
}

/// `p` as a non-zero [`BoxedUint`] divisor at the given precision.
fn nz_prime_at(p: u64, precision: u32) -> NonZero<BoxedUint> {
    let p_big = at_precision(BoxedUint::from(p), precision);
    NonZero::new(p_big)
        .into_option()
        .expect("a prime > 3 is non-zero")
}

/// `a · b mod p` for `u64` operands, via a 128-bit intermediate.
fn mulmod_u64(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 * b as u128) % p as u128) as u64
}

/// `a⁻¹ mod m` for a prime modulus `m`, via the extended Euclidean algorithm.
///
/// # Panics (debug)
///
/// Debug-asserts that `gcd(a, m) = 1`.
fn inv_mod_u64(a: u64, m: u64) -> u64 {
    debug_assert!(m > 1);
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (m as i128, (a % m) as i128);
    while new_r != 0 {
        let q = r / new_r;
        (t, new_t) = (new_t, t - q * new_t);
        (r, new_r) = (new_r, r - q * new_r);
    }
    debug_assert_eq!(r, 1, "{a} is not invertible mod {m}");
    let m_i = m as i128;
    (((t % m_i) + m_i) % m_i) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ceil_log2(n)` is the smallest `k` with `2^k ≥ n` (`0` at `n = 1`).
    #[test]
    fn ceil_log2_matches_reference() {
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(174), 8); // the P-256 CRT-prime count
        for n in 1u32..4000 {
            let k = ceil_log2(n);
            assert!(1u64 << k >= n as u64, "2^{k} < {n}");
            if k > 0 {
                assert!(
                    1u64 << (k - 1) < n as u64,
                    "{n} ≤ 2^{} — not minimal",
                    k - 1
                );
            }
        }
    }

    /// `mulmod_u64` equals the u128 reference, including when `a·b` overflows
    /// u64.
    #[test]
    fn mulmod_u64_matches_reference() {
        for (a, b, p) in [
            (0u64, 0u64, 7u64),
            (3, 4, 5),
            (6, 6, 7),
            (1063, 1062, 1063),
            (u64::MAX, u64::MAX, 1_000_000_007),
            (1 << 40, 1 << 40, 1_000_003), // a·b ≫ 2⁶⁴
        ] {
            assert_eq!(
                mulmod_u64(a, b, p),
                ((a as u128 * b as u128) % p as u128) as u64,
                "a={a} b={b} p={p}"
            );
        }
    }

    /// `inv_mod_u64(a, m)` is the reduced inverse: `a · a⁻¹ ≡ 1 (mod m)` for
    /// every nonzero `a` over several primes `m`.
    #[test]
    fn inv_mod_u64_inverts() {
        for &m in &[5u64, 7, 97, 1009, 1063] {
            for a in 1..m {
                let inv = inv_mod_u64(a, m);
                assert!(inv < m, "inverse not reduced: a={a} m={m} inv={inv}");
                assert_eq!(mulmod_u64(a, inv, m), 1, "a={a} m={m}");
            }
        }
    }

    /// Small worked example: n = 5·7·11 = 385.
    #[test]
    fn small_example_round_trip() {
        let basis = CrtSystem::new(vec![5, 7, 11]);
        assert_eq!(
            basis.modulus(),
            &at_precision(BoxedUint::from(385u64), basis.precision())
        );

        // 100 mod (5,7,11) = (0,2,1)
        let x = at_precision(BoxedUint::from(100u64), basis.precision());
        assert_eq!(basis.encode(&x), vec![0, 2, 1]);
        assert_eq!(basis.decode(&[0, 2, 1]), x);
    }

    /// `decode` then `encode` is the identity on residue vectors.
    #[test]
    fn residues_round_trip() {
        let basis = CrtSystem::new(crate::dhim::config::p256::P256_PRIMES[..40].to_vec());
        let primes = basis.primes().to_vec();

        // A deterministic spread of residues in range.
        let residues: Vec<u64> = primes
            .iter()
            .enumerate()
            .map(|(i, &p)| ((i as u64 * 2654435761) ^ 0x9e37) % p)
            .collect();

        let x = basis.decode(&residues);
        assert_eq!(basis.encode(&x), residues);

        // And the defining congruences hold directly.
        for (i, &p) in primes.iter().enumerate() {
            // Independent full-division check that encode's reciprocal path agrees.
            let p_nz = nz_prime_at(p, basis.precision());
            assert_eq!(x.rem_vartime(&p_nz).as_words()[0], residues[i]);
        }
    }

    /// `encode` then `decode` is the identity on `Z_n`, at the production CRT
    /// basis (the precise [`crate::dhim::config::p256::P256_PRIMES`]); also
    /// pins down |n|.
    #[test]
    fn values_round_trip_full_basis() {
        let basis = CrtSystem::new(crate::dhim::config::p256::P256_PRIMES.to_vec());

        // The smooth modulus for the |q|=256 set is ~1460 bits.
        let bits = basis.modulus().bits();
        assert!(
            (1400..=1520).contains(&bits),
            "|n| = {bits} bits, expected ≈1460"
        );

        // Deterministic pseudo-random x < n (LCG-filled big-endian bytes,
        // reduced mod n) — no RNG dependency in tests.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next_byte = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        let nbytes = (basis.precision() / 8) as usize;

        for _ in 0..20 {
            let bytes: Vec<u8> = (0..nbytes).map(|_| next_byte()).collect();
            let raw = BoxedUint::from_be_slice(&bytes, basis.precision()).unwrap();
            let x = raw.rem_vartime(basis.modulus_nz());

            let residues = basis.encode(&x);
            assert_eq!(basis.decode(&residues), x);
        }
    }
}
