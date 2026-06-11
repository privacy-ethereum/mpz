//! This module implements the extension field GF(2^128).

use hybrid_array::{
    Array,
    typenum::{U16, U128},
};
use itybity::{BitLength, FromBitIterator, GetBit, Lsb0, Msb0, SetBit};
use rand::{distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Neg, Sub};

use mpz_core::Block;

use std::sync::LazyLock;

use crate::{ExtensionField, Field, FieldError, gf2::Gf2, gf2_64::Gf2_64};

/// A type for holding field elements of Gf(2^128).
#[derive(
    Copy,
    Clone,
    Default,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
)]
#[repr(transparent)]
pub struct Gf2_128(pub(crate) u128);

opaque_debug::implement!(Gf2_128);

impl Gf2_128 {
    /// The additive identity (zero).
    pub const ZERO: Self = Gf2_128(0);
    /// The multiplicative identity (one).
    pub const ONE: Self = Gf2_128(1);

    /// Creates a new field element from a u128,
    /// mapping the integer to the corresponding polynomial.
    ///
    /// For example, 5u128 is mapped to the polynomial `1 + x^2`.
    pub const fn new(input: u128) -> Self {
        Gf2_128(input)
    }

    /// Returns the field element as a u128.
    pub const fn to_inner(self) -> u128 {
        self.0
    }
}

impl From<Gf2_128> for Block {
    fn from(value: Gf2_128) -> Self {
        Block::new(value.0.to_le_bytes())
    }
}

impl From<Block> for Gf2_128 {
    fn from(block: Block) -> Self {
        Gf2_128(u128::from_le_bytes(block.to_bytes()))
    }
}

impl TryFrom<Array<u8, U16>> for Gf2_128 {
    type Error = FieldError;

    fn try_from(value: Array<u8, U16>) -> Result<Self, Self::Error> {
        let inner: [u8; 16] = value.into();

        Ok(Gf2_128(u128::from_le_bytes(inner)))
    }
}

impl Distribution<Gf2_128> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Gf2_128 {
        Gf2_128(self.sample(rng))
    }
}

impl Add for Gf2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub for Gf2_128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2_128 {
    type Output = Self;

    /// Galois field multiplication of two 128-bit blocks reduced by the GCM
    /// polynomial.
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        // See NIST SP 800-38D, Recommendation for Block Cipher Modes of Operation:
        // Galois/Counter Mode (GCM) and GMAC.
        //
        // Note that the NIST specification uses a different representation of the
        // polynomial, where the bits are reversed. This "bit reflection" is
        // discussed in Intel® Carry-Less Multiplication Instruction and its Usage for
        // Computing the GCM Mode.
        //
        // The irreducible polynomial is the same, ie `x^128 + x^7 + x^2 + x + 1`.
        Gf2_128(gf128_mul(self.0, rhs.0))
    }
}

impl Neg for Gf2_128 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Field for Gf2_128 {
    type BitSize = U128;

    type ByteSize = U16;

    type Accumulator = Gf2_128Accumulator;

    fn zero() -> Self {
        Self::new(0)
    }

    fn one() -> Self {
        Self::new(1)
    }

    fn two_pow(rhs: u32) -> Self {
        Self(1 << rhs)
    }

    /// Galois field inversion of 128-bit block.
    fn inverse(self) -> Option<Self> {
        if self == Self::zero() {
            return None;
        }
        Some(Gf2_128(gf128_inverse(self.0)))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }

    #[inline]
    fn inner_product_chunk(a: &[Self], b: &[Self]) -> Self {
        Gf2_128(gf128_inner_product(a, b))
    }

    #[inline]
    fn double_inner_product_chunk(a: &[Self], b: &[Self], c: &[Self]) -> Self {
        Gf2_128(gf128_double_inner_product(a, b, c))
    }

    #[inline]
    fn square(self) -> Self {
        Gf2_128(gf128_square(self.0))
    }
}

/// Deferred-reduction [`Accumulator`](crate::Accumulator) for [`Gf2_128`].
///
/// Holds the XOR of unreduced 256-bit carry-less products as `(lo, hi)` and
/// reduces once modulo `p(x) = x¹²⁸ + x⁷ + x² + x + 1`. Reduction is linear
/// over XOR, so reducing the accumulated sum equals the field sum of the
/// individual products.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Gf2_128Accumulator {
    lo: u128,
    hi: u128,
}

impl crate::Accumulator for Gf2_128Accumulator {
    type Field = Gf2_128;

    #[inline]
    fn zero() -> Self {
        Self { lo: 0, hi: 0 }
    }

    #[inline]
    fn from_field(value: Gf2_128) -> Self {
        // A reduced element is already `< x¹²⁸`, so it sits entirely in `lo`;
        // reducing `(value, 0)` is the identity.
        Self { lo: value.0, hi: 0 }
    }

    #[inline]
    fn add_product(&mut self, a: Gf2_128, b: Gf2_128) {
        let (lo, hi) = gf128_mul_full(a.0, b.0);
        self.lo ^= lo;
        self.hi ^= hi;
    }

    #[inline]
    fn merge(&mut self, other: &Self) {
        self.lo ^= other.lo;
        self.hi ^= other.hi;
    }

    #[inline]
    fn reduce(self) -> Gf2_128 {
        Gf2_128(gf128_reduce(self.lo, self.hi))
    }
}

/// Monomial basis `[α^0, α^1, …, α^127]` of `GF(2^128)` over `GF(2)`.
static MONOMIAL_BASIS_GF2_128: [Gf2_128; 128] = {
    let mut out = [Gf2_128::new(0); 128];
    let mut i = 0;
    while i < 128 {
        out[i] = Gf2_128::new(1u128 << i);
        i += 1;
    }
    out
};

impl ExtensionField<Gf2> for Gf2_128 {
    const MONOMIAL_BASIS: &'static [Self] = &MONOMIAL_BASIS_GF2_128;

    #[inline]
    fn embed(base: Gf2) -> Self {
        // `Gf2(false) -> 0`, `Gf2(true) -> 1`.
        Gf2_128::new(u128::from(base.0))
    }

    /// Branchless masked AND — drops `self` to zero when `base` is
    /// false, leaves it unchanged when true.
    #[inline]
    fn scale_by_subfield(self, base: Gf2) -> Self {
        let mask = (base.0 as u128).wrapping_neg();
        Gf2_128::new(self.0 & mask)
    }

    /// Constant-time masked XOR: each term reduces to
    /// `acc ^= c & mask_from_bit(v)` — no field multiplications and
    /// no data-dependent branches.
    #[inline]
    fn inner_product_subfield(values: &[Gf2], challenges: &[Self]) -> Self {
        assert_eq!(
            values.len(),
            challenges.len(),
            "inner_product_subfield: slice length mismatch",
        );
        let mut acc = 0u128;
        for (v, c) in values.iter().zip(challenges.iter()) {
            // `v.0 as u128` is 0 or 1; `wrapping_neg()` gives 0 or
            // `u128::MAX`. ANDing with `c.to_inner()` zeroes out the
            // term when `v == Gf2(0)` without branching.
            let mask = (v.0 as u128).wrapping_neg();
            acc ^= c.to_inner() & mask;
        }
        Gf2_128::new(acc)
    }
}

/// Trivial self-extension: degree-1, basis `[1]`, embed is identity.
impl ExtensionField<Gf2_128> for Gf2_128 {
    const MONOMIAL_BASIS: &'static [Self] = &[Gf2_128::ONE];

    #[inline]
    fn embed(base: Gf2_128) -> Self {
        base
    }

    #[inline]
    fn inner_product_subfield(values: &[Gf2_128], challenges: &[Self]) -> Self {
        Gf2_128::inner_product(values, challenges)
    }
}

/// A root in GF(2^128) of `Gf2_64`'s modulus `q(x) = x^64 + x^4 + x^3 + x + 1`,
/// i.e. the image of the `Gf2_64` generator `x` under the subfield embedding
/// GF(2^64) ↪ GF(2^128). Derived once by the `derive_gf2_64_embedding` test.
const GF2_64_EMBED_ROOT: u128 = 0xb2fa_452a_ba89_6b2a_bf36_31f0_bfe3_992a;

/// The embedding map as a basis `[r^0, r^1, …, r^63]`: `embed(b) = Σ bᵢ·rⁱ`,
/// the GF(2)-linear extension of `x ↦ r`. Built once from
/// [`GF2_64_EMBED_ROOT`].
static GF2_64_EMBED_BASIS: LazyLock<[Gf2_128; 64]> = LazyLock::new(|| {
    let r = Gf2_128::new(GF2_64_EMBED_ROOT);
    let mut basis = [Gf2_128::ONE; 64];
    for i in 1..64 {
        basis[i] = basis[i - 1] * r;
    }
    basis
});

/// Monomial basis `[1, x]` of GF(2^128) as a degree-2 extension of the
/// embedded GF(2^64): `x = Gf2_128::new(2)` lies outside the subfield, so
/// `{1, x}` is a GF(2^64)-basis (verified in `derive_gf2_64_embedding`).
static MONOMIAL_BASIS_GF2_64: [Gf2_128; 2] = [Gf2_128::new(1), Gf2_128::new(2)];

impl ExtensionField<Gf2_64> for Gf2_128 {
    const MONOMIAL_BASIS: &'static [Self] = &MONOMIAL_BASIS_GF2_64;

    /// The subfield injection GF(2^64) ↪ GF(2^128): the GF(2)-linear extension
    /// of `x ↦ r` (a root of GF(2^64)'s modulus), which is a field
    /// homomorphism.
    ///
    /// Constant-time masked XOR: each basis term is gated by
    /// `acc ^= basis[i] & mask_from_bit(i)` — no data-dependent branches, so
    /// witness values stay branch-free on the prover hot path (reached via
    /// [`scale_by_subfield`](Self::scale_by_subfield)).
    #[inline]
    fn embed(base: Gf2_64) -> Self {
        let bits = base.0;
        let basis = &*GF2_64_EMBED_BASIS;
        let mut acc = 0u128;
        for (i, &b) in basis.iter().enumerate() {
            // `(bits >> i) & 1` is 0 or 1; `wrapping_neg()` gives 0 or
            // `u128::MAX`, zeroing the term when bit `i` is unset.
            let mask = (((bits >> i) & 1) as u128).wrapping_neg();
            acc ^= b.to_inner() & mask;
        }
        Gf2_128::new(acc)
    }

    #[inline]
    fn scale_by_subfield(self, base: Gf2_64) -> Self {
        self * Self::embed(base)
    }
}

cfg_select! {
    target_arch = "x86_64" => {
        // Dispatch to the PCLMULQDQ backend via runtime detection, falling
        // back to the software backend. When PCLMULQDQ is enabled at compile
        // time, `cpufeatures` elides the runtime check entirely. (Calling the
        // `#[target_feature]` functions directly would require `unsafe` even
        // then, so the static case routes through here too.)
        mod autodetect;
        mod soft;
        mod x86;
        use autodetect as backend;
    }
    all(target_arch = "wasm32", target_feature = "simd128") => {
        mod wasm;
        use wasm as backend;
    }
    _ => {
        mod soft;
        use soft as backend;
    }
}

#[inline(always)]
fn gf128_mul(a: u128, b: u128) -> u128 {
    backend::mul(a, b)
}

#[inline(always)]
fn gf128_inner_product(a: &[Gf2_128], b: &[Gf2_128]) -> u128 {
    backend::inner_product(a, b)
}

#[inline(always)]
fn gf128_double_inner_product(a: &[Gf2_128], b: &[Gf2_128], c: &[Gf2_128]) -> u128 {
    backend::double_inner_product(a, b, c)
}

#[inline(always)]
fn gf128_mul_full(a: u128, b: u128) -> (u128, u128) {
    backend::mul_full(a, b)
}

#[inline(always)]
fn gf128_reduce(lo: u128, hi: u128) -> u128 {
    backend::reduce(lo, hi)
}

#[inline(always)]
fn gf128_inverse(a: u128) -> u128 {
    backend::inverse(a)
}

#[inline(always)]
fn gf128_square(a: u128) -> u128 {
    backend::square(a)
}

impl BitLength for Gf2_128 {
    const BITS: usize = 128;
}

impl GetBit<Lsb0> for Gf2_128 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Lsb0>::get_bit(&self.0, index)
    }
}

impl GetBit<Msb0> for Gf2_128 {
    fn get_bit(&self, index: usize) -> bool {
        GetBit::<Msb0>::get_bit(&self.0, index)
    }
}

impl SetBit<Lsb0> for Gf2_128 {
    fn set_bit(&mut self, index: usize, value: bool) {
        SetBit::<Lsb0>::set_bit(&mut self.0, index, value)
    }
}

impl SetBit<Msb0> for Gf2_128 {
    fn set_bit(&mut self, index: usize, value: bool) {
        SetBit::<Msb0>::set_bit(&mut self.0, index, value)
    }
}

impl FromBitIterator for Gf2_128 {
    fn from_lsb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Self(u128::from_lsb0_iter(iter))
    }

    fn from_msb0_iter(iter: impl IntoIterator<Item = bool>) -> Self {
        Self(u128::from_msb0_iter(iter))
    }
}

#[cfg(test)]
mod tests {
    use super::Gf2_128;
    use crate::{
        ExtensionField, Field,
        gf2::Gf2,
        tests::{
            test_extension_field_subfield_inner_product, test_field_accumulator,
            test_field_axioms_random, test_field_basic, test_field_bit_ops_lsb0,
            test_field_bit_ops_msb0, test_field_compute_product_repeated,
            test_field_double_inner_product, test_field_inner_product, test_field_set_bit_lsb0,
            test_field_set_bit_msb0, test_field_square,
        },
    };

    /// One-time derivation of the GF(2^64) ↪ GF(2^128) embedding constant: a
    /// root in GF(2^128) of `Gf2_64`'s modulus `q(x) = x^64 + x^4 + x^3 + x +
    /// 1`. Run with `--nocapture` and bake the printed value as a constant.
    ///
    /// Cantor equal-degree root finding: `q` splits into 64 distinct linear
    /// factors over GF(2^128); the trace map `Tr(a·x) = Σ_{i<128} (a·x)^(2^i)`
    /// down to GF(2) splits the factors by `Tr(a·root) ∈ {0,1}`, and repeated
    /// gcds isolate one linear factor.
    #[test]
    #[ignore = "one-time derivation; prints the embedding constant"]
    fn derive_gf2_64_embedding() {
        use rand::{Rng, SeedableRng, rngs::StdRng};

        type P = Vec<Gf2_128>; // coeffs low→high, no trailing zeros

        fn norm(mut p: P) -> P {
            while p.last() == Some(&Gf2_128::ZERO) {
                p.pop();
            }
            p
        }
        fn deg(p: &P) -> isize {
            p.len() as isize - 1
        }
        fn add(a: &P, b: &P) -> P {
            let n = a.len().max(b.len());
            norm(
                (0..n)
                    .map(|i| {
                        *a.get(i).unwrap_or(&Gf2_128::ZERO) + *b.get(i).unwrap_or(&Gf2_128::ZERO)
                    })
                    .collect(),
            )
        }
        fn scale(a: &P, s: Gf2_128) -> P {
            norm(a.iter().map(|&c| c * s).collect())
        }
        fn mul(a: &P, b: &P) -> P {
            if a.is_empty() || b.is_empty() {
                return vec![];
            }
            let mut out = vec![Gf2_128::ZERO; a.len() + b.len() - 1];
            for (i, &x) in a.iter().enumerate() {
                for (j, &y) in b.iter().enumerate() {
                    out[i + j] = out[i + j] + x * y;
                }
            }
            norm(out)
        }
        // Remainder of `a` modulo monic-able `m` (leading coeff inverted).
        fn rem(a: &P, m: &P) -> P {
            let mut a = norm(a.clone());
            let lead_inv = m.last().unwrap().inverse().unwrap();
            while deg(&a) >= deg(m) && !a.is_empty() {
                let shift = (deg(&a) - deg(m)) as usize;
                let factor = *a.last().unwrap() * lead_inv;
                let mut sub = vec![Gf2_128::ZERO; shift];
                sub.extend(m.iter().map(|&c| c * factor));
                a = add(&a, &sub);
            }
            a
        }
        fn gcd(mut a: P, mut b: P) -> P {
            a = norm(a);
            b = norm(b);
            while !b.is_empty() {
                let r = rem(&a, &b);
                a = b;
                b = r;
            }
            if let Some(&lead) = a.last() {
                let inv = lead.inverse().unwrap();
                a = scale(&a, inv);
            }
            a
        }

        // q(x) = x^64 + x^4 + x^3 + x + 1.
        let mut q = vec![Gf2_128::ZERO; 65];
        for i in [0usize, 1, 3, 4, 64] {
            q[i] = Gf2_128::ONE;
        }

        // x^(2^i) mod q for i = 0..128.
        let mut xpow = vec![vec![Gf2_128::ZERO, Gf2_128::ONE]]; // x
        for i in 1..128 {
            let sq = mul(&xpow[i - 1], &xpow[i - 1]);
            xpow.push(rem(&sq, &q));
        }

        // Split `f` until a linear factor (one root) is isolated.
        fn split(f: &P, xpow: &[P], q: &P, rng: &mut StdRng) -> Gf2_128 {
            if deg(f) == 1 {
                // f = c1·x + c0  ⇒  root = c0 / c1.
                return f[0] * f[1].inverse().unwrap();
            }
            loop {
                let a = Gf2_128::new(rng.random());
                // Tr(a·x) mod q = Σ_i a^(2^i) · x^(2^i).
                let mut tr: P = vec![];
                let mut apow = a;
                for xq in xpow.iter() {
                    tr = add(&tr, &scale(xq, apow));
                    apow = apow * apow;
                }
                let g = gcd(f.clone(), rem(&tr, q));
                if deg(&g) >= 1 && deg(&g) < deg(f) {
                    return split(&g, xpow, q, rng);
                }
            }
        }

        let mut rng = StdRng::seed_from_u64(0x6420_1128);
        let r = split(&q, &xpow, &q, &mut rng);

        // Verify q(r) = 0.
        let mut acc = Gf2_128::ZERO;
        let mut rp = Gf2_128::ONE;
        for &qi in &q {
            if qi != Gf2_128::ZERO {
                acc = acc + rp;
            }
            rp = rp * r;
        }
        assert_eq!(acc, Gf2_128::ZERO, "r must be a root of q");

        // A monomial-basis second element θ ∉ subfield (θ^(2^64) ≠ θ).
        let frob64 = |mut z: Gf2_128| {
            for _ in 0..64 {
                z = z * z;
            }
            z
        };
        let x = Gf2_128::new(2);
        assert_ne!(frob64(x), x, "x must lie outside GF(2^64) for the basis");

        println!("GF2_64 embedding root r = 0x{:032x}", r.to_inner());
    }

    /// The GF(2^64) ↪ GF(2^128) embedding is a ring homomorphism: it preserves
    /// `1`, addition, and multiplication, so authenticating GF(2^64) values
    /// with GF(2^128) MACs is consistent.
    #[test]
    fn gf2_64_embedding_is_homomorphism() {
        use crate::gf2_64::Gf2_64;
        use rand::{Rng, SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(0x6420_1129);
        assert_eq!(
            <Gf2_128 as ExtensionField<Gf2_64>>::embed(Gf2_64::ONE),
            Gf2_128::ONE,
        );
        assert_eq!(
            <Gf2_128 as ExtensionField<Gf2_64>>::embed(Gf2_64::ZERO),
            Gf2_128::ZERO,
        );
        for _ in 0..512 {
            let a = Gf2_64(rng.random());
            let b = Gf2_64(rng.random());
            let ea = <Gf2_128 as ExtensionField<Gf2_64>>::embed(a);
            let eb = <Gf2_128 as ExtensionField<Gf2_64>>::embed(b);
            assert_eq!(
                <Gf2_128 as ExtensionField<Gf2_64>>::embed(a + b),
                ea + eb,
                "additive",
            );
            assert_eq!(
                <Gf2_128 as ExtensionField<Gf2_64>>::embed(a * b),
                ea * eb,
                "multiplicative",
            );
            // `scale_by_subfield` agrees with embed-then-multiply.
            let m = Gf2_128::new(rng.random());
            assert_eq!(m.scale_by_subfield(a), m * ea);
        }
    }

    #[test]
    fn test_gf2_128_basic() {
        test_field_basic::<Gf2_128>();
        assert_eq!(Gf2_128::new(0), Gf2_128::zero());
        assert_eq!(Gf2_128::new(1), Gf2_128::one());
    }

    #[test]
    fn test_gf2_128_compute_product_repeated() {
        test_field_compute_product_repeated::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_inner_product() {
        test_field_inner_product::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_double_inner_product() {
        test_field_double_inner_product::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_accumulator() {
        test_field_accumulator::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_axioms_random() {
        test_field_axioms_random::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_square() {
        test_field_square::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_bit_ops() {
        test_field_bit_ops_lsb0::<Gf2_128>();
        test_field_bit_ops_msb0::<Gf2_128>();
        test_field_set_bit_lsb0::<Gf2_128>();
        test_field_set_bit_msb0::<Gf2_128>();
    }

    #[test]
    fn test_gf2_128_subfield_inner_product() {
        test_extension_field_subfield_inner_product::<Gf2_128, Gf2>();
    }

    #[test]
    #[should_panic(expected = "inner_product: slice length mismatch")]
    fn test_gf2_128_inner_product_length_mismatch() {
        let a = [Gf2_128::new(1), Gf2_128::new(1)];
        let b = [Gf2_128::new(1)];
        let _ = Gf2_128::inner_product(&a, &b);
    }

    #[test]
    fn test_gf2_128_reduction_constant() {
        // p(x) = x¹²⁸ + x⁷ + x² + x + 1, so x¹²⁸ ≡ R = x⁷+x²+x+1 = 0x87.
        assert_eq!(Gf2_128::new(1 << 127) * Gf2_128::new(2), Gf2_128::new(0x87));
        // x¹²⁹ = x·R = x⁸ + x³ + x² + x = 0x10e.
        assert_eq!(
            Gf2_128::new(1 << 127) * Gf2_128::new(4),
            Gf2_128::new(0x10e)
        );
    }

    #[test]
    fn test_gf2_128_inv_round_trip() {
        for raw in [
            1u128,
            2,
            3,
            0x87, // reduction constant R
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
            1u128 << 127,                       // top bit
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, // all ones
            0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, // alternating
            0x7b5b54657374566563746f725d53475d, // Intel test vector operand
        ] {
            let x = Gf2_128::new(raw);
            let xi = x.inverse().unwrap();
            assert_eq!(x * xi, Gf2_128::one(), "x={raw:#034x}");
        }
        assert_eq!(Gf2_128::zero().inverse(), None);
    }

    #[test]
    fn test_gf2_128_mul() {
        for &(a, b, expected) in REFERENCE_PRODUCTS {
            let ours = (Gf2_128::new(a) * Gf2_128::new(b)).0;
            assert_eq!(
                ours, expected,
                "mismatch: a={a:#034x} b={b:#034x} ours={ours:#034x} expected={expected:#034x}"
            );
            // Commutativity spot-check on every vector.
            assert_eq!(
                Gf2_128::new(a) * Gf2_128::new(b),
                Gf2_128::new(b) * Gf2_128::new(a)
            );
        }
    }

    /// Reference products `(a, b, a·b)` in GF(2¹²⁸) under
    /// p(x) = x¹²⁸ + x⁷ + x² + x + 1. Values 0–10 are derived algebraically
    /// from the irreducible polynomial; the last entry is from Intel's
    /// Carry-Less Multiplication white paper.
    const REFERENCE_PRODUCTS: &[(u128, u128, u128)] = &[
        // identity / zero
        (0, 0, 0),
        (0, 0xDEADBEEFCAFEBABE0123456789ABCDEF, 0),
        (
            1,
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
        ),
        (
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
            1,
            0xDEADBEEFCAFEBABE0123456789ABCDEF,
        ),
        // no-reduction cases
        (2, 2, 4),  // x · x = x²
        (3, 5, 15), // (1+x)(1+x²) = 1+x+x²+x³
        (3, 7, 9),  // (1+x)(1+x+x²) = 1 + x³
        // reduction-triggering cases (derived from x¹²⁸ ≡ x⁷+x²+x+1)
        (1 << 127, 2, 0x87),  // x¹²⁷ · x = x¹²⁸ ≡ R
        (1 << 127, 4, 0x10e), // x¹²⁷ · x² = x¹²⁹ = x·R = x⁸+x³+x²+x
        (0x87, 0x87, 0x4015), // R² = x¹⁴+x⁴+x²+1 (Freshman's dream)
        // x¹²⁷ · x¹²⁷ = x²⁵⁴ ≡ x¹²⁷+x¹²⁶+x¹²+x⁶+x⁵+x²+x+1
        (1 << 127, 1 << 127, 0xC0000000000000000000000000001067),
        // Intel® Carry-Less Multiplication Instruction white paper
        (
            0x7b5b54657374566563746f725d53475d,
            0x48692853686179295b477565726f6e5d,
            0x40229a09a5ed12e7e4e10da323506d2,
        ),
    ];
}
