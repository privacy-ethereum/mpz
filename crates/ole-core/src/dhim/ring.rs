//! Runtime-modulus residue ring `Z_m` for an odd modulus `m`.

use crypto_bigint::{
    BoxedUint, NonZero, Odd, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};

/// The residue ring `Z_m` for an odd modulus `m`.
#[derive(Clone)]
pub struct Ring {
    /// Montgomery parameters for `m`.
    params: BoxedMontyParams,
    /// The modulus `m`.
    modulus: BoxedUint,
    /// Shared bit precision of every [`BoxedUint`] representative in this ring.
    precision: u32,
}

impl Ring {
    /// Creates `Z_m` for an odd modulus `m`.
    ///
    /// # Panics
    ///
    /// Panics if `m` is even or zero (the Montgomery backend requires an odd
    /// modulus).
    pub fn new(modulus: BoxedUint) -> Self {
        let precision = modulus.bits_precision();
        let odd = Odd::new(modulus.clone())
            .into_option()
            .expect("residue-ring modulus must be odd and non-zero");
        let params = BoxedMontyParams::new(odd);
        Self {
            params,
            modulus,
            precision,
        }
    }

    /// The modulus `m`.
    pub fn modulus(&self) -> &BoxedUint {
        &self.modulus
    }

    /// The bit precision of the ring's [`BoxedUint`] representatives.
    pub fn precision(&self) -> u32 {
        self.precision
    }

    /// The additive identity `0`.
    pub fn zero(&self) -> Elem {
        Elem {
            inner: BoxedMontyForm::zero(&self.params),
        }
    }

    /// The multiplicative identity `1`.
    pub fn one(&self) -> Elem {
        Elem {
            inner: BoxedMontyForm::one(&self.params),
        }
    }

    /// Embeds a big integer `v` into the ring, reducing it by the ring modulus.
    /// Non-constant-time implementation.
    ///
    /// `v` may be given at **any** precision — in particular wider than the
    /// ring's own.
    // `from_*` reads as a free constructor to clippy, but embedding genuinely
    // needs the ring's Montgomery params, hence `&self`.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_uint(&self, v: &BoxedUint) -> Elem {
        let reduced = if v.bits_precision() > self.precision {
            // Reduce at the input's (wider) precision, then shrink the `< m`
            // result down to the ring precision.
            let m_wide = self.modulus.clone().resize(v.bits_precision());
            let m_wide_nz = NonZero::new(m_wide)
                .into_option()
                .expect("residue-ring modulus is non-zero");
            v.rem_vartime(&m_wide_nz).resize(self.precision)
        } else {
            v.clone().resize(self.precision)
        };
        Elem {
            inner: BoxedMontyForm::new(reduced, &self.params),
        }
    }

    /// Embeds a `u64` into the ring.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_u64(&self, v: u64) -> Elem {
        self.from_uint(&BoxedUint::from(v))
    }
}

/// An element of a [`Ring`] (`Z_m`).
#[derive(Clone, PartialEq, Eq)]
pub struct Elem {
    inner: BoxedMontyForm,
}

impl Elem {
    /// Returns the canonical representative in `[0, m)`.
    pub fn to_uint(&self) -> BoxedUint {
        self.inner.retrieve()
    }

    /// Returns the multiplicative inverse, or `None` if `self` is not
    /// invertible mod `m`.
    pub fn inverse(&self) -> Option<Elem> {
        self.inner
            .invert()
            .into_option()
            .map(|inner| Elem { inner })
    }

    /// Returns `self` raised to the power `exponent`.
    pub fn pow(&self, exponent: &BoxedUint) -> Elem {
        Elem {
            inner: self.inner.pow(exponent),
        }
    }
}

impl core::fmt::Debug for Elem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Elem({:?})", self.inner.retrieve())
    }
}

/// Generates the owned and borrowed forms of a binary operator, dispatching to
/// [`BoxedMontyForm`]'s by-reference operator impls (which borrow both operands
/// rather than consume them).
macro_rules! impl_binop {
    ($trait:ident, $method:ident) => {
        impl core::ops::$trait<Elem> for Elem {
            type Output = Elem;
            fn $method(self, rhs: Elem) -> Elem {
                Elem {
                    inner: core::ops::$trait::$method(&self.inner, &rhs.inner),
                }
            }
        }
        impl core::ops::$trait<&Elem> for &Elem {
            type Output = Elem;
            fn $method(self, rhs: &Elem) -> Elem {
                Elem {
                    inner: core::ops::$trait::$method(&self.inner, &rhs.inner),
                }
            }
        }
    };
}

impl_binop!(Add, add);
impl_binop!(Sub, sub);
impl_binop!(Mul, mul);

impl core::ops::Neg for Elem {
    type Output = Elem;
    fn neg(self) -> Elem {
        Elem {
            inner: core::ops::Neg::neg(&self.inner),
        }
    }
}

impl core::ops::Neg for &Elem {
    type Output = Elem;
    fn neg(self) -> Elem {
        Elem {
            inner: core::ops::Neg::neg(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhim::{crt::CrtSystem, rng::Compat};
    use crypto_bigint::{ConcatenatingMul, RandomMod};
    use mpz_core::prg::Prg;
    use rand::RngCore;

    /// Samples a uniformly random element of `ring`.
    fn random_elem<R: RngCore + ?Sized>(ring: &Ring, rng: &mut R) -> Elem {
        let v = BoxedUint::random_mod_vartime(&mut Compat(rng), &ring_modulus_nz(ring));
        ring.from_uint(&v)
    }

    /// A small odd-prime ring checked against `u128` reference arithmetic.
    #[test]
    fn small_prime_ring_axioms() {
        let m = 97u64;
        let ring = Ring::new(BoxedUint::from(m));

        let red = |e: &Elem| -> u64 { e.to_uint().as_words().first().copied().unwrap_or(0) };

        for a in 0..m {
            for b in 0..m {
                let ea = ring.from_u64(a);
                let eb = ring.from_u64(b);
                assert_eq!(red(&(&ea + &eb)), (a + b) % m);
                assert_eq!(red(&(&ea - &eb)), (a + m - b) % m);
                assert_eq!(red(&(&ea * &eb)), (a * b) % m);
            }
            let ea = ring.from_u64(a);
            assert_eq!(red(&(-&ea)), (m - a) % m);
        }
    }

    #[test]
    fn inverse_and_pow() {
        let ring = Ring::new(BoxedUint::from(97u64));
        let one = ring.one();

        // a · a⁻¹ = 1 for every non-zero a.
        for a in 1..97u64 {
            let ea = ring.from_u64(a);
            let inv = ea.inverse().expect("non-zero is invertible mod prime");
            assert_eq!(&ea * &inv, one);
        }
        // 0 is not invertible.
        assert!(ring.zero().inverse().is_none());

        // 2^10 = 1024 ≡ 51 (mod 97).
        let two = ring.from_u64(2);
        assert_eq!(two.pow(&BoxedUint::from(10u64)), ring.from_u64(1024 % 97));
    }

    /// Z_n over the smooth modulus: ring axioms and sampling stay in range.
    #[test]
    fn smooth_modulus_ring() {
        let basis = CrtSystem::new(crate::dhim::config::p256::P256_PRIMES.to_vec());
        let ring = Ring::new(basis.modulus().clone());
        let mut rng = Prg::new_with_seed([0u8; 16]);

        let zero = ring.zero();
        let one = ring.one();

        for _ in 0..50 {
            let a = random_elem(&ring, &mut rng);
            let b = random_elem(&ring, &mut rng);

            // Sampled representatives are reduced.
            assert!(a.to_uint() < *ring.modulus());

            // Ring axioms.
            assert_eq!(&a + &b, &b + &a);
            assert_eq!(&(&a - &b) + &b, a.clone());
            assert_eq!(&a + &(-&a), zero);
            assert_eq!(&a * &one, a.clone());
            assert_eq!(&a * &b, &b * &a);
        }

        // Multiplication agrees with a direct mod-n bigint multiply.
        let a = random_elem(&ring, &mut rng);
        let b = random_elem(&ring, &mut rng);
        let prod_direct = a
            .to_uint()
            .concatenating_mul(&b.to_uint())
            .rem_vartime(&ring_modulus_nz(&ring));
        assert_eq!((&a * &b).to_uint(), prod_direct.resize(ring.precision()));
    }

    fn ring_modulus_nz(ring: &Ring) -> NonZero<BoxedUint> {
        NonZero::new(ring.modulus().clone())
            .into_option()
            .expect("ring modulus is non-zero")
    }

    /// Reducing a wide `Z_n`-sized value into a small ring (`Z_r`-style) must
    /// agree with a direct big-integer remainder — i.e. no high-bit truncation.
    #[test]
    fn reduce_wide_input_into_small_ring() {
        let basis = CrtSystem::new(crate::dhim::config::p256::P256_PRIMES.to_vec()); // |n| ≈ 1458 bits
        let big = basis.modulus().clone(); // a genuine ~1458-bit value

        let small = Ring::new(BoxedUint::from(1_000_003u64)); // a prime ≪ n
        let embedded = small.from_uint(&big);

        // Direct reference: big mod 1_000_003, computed at the wide precision.
        let m_wide = BoxedUint::from(1_000_003u64).resize(big.bits_precision());
        let m_nz = NonZero::new(m_wide).into_option().unwrap();
        let expected = big.rem_vartime(&m_nz).resize(small.precision());

        assert_eq!(embedded.to_uint(), expected);
    }
}
