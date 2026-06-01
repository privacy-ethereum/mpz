//! Authenticated wire types.

use mpz_fields::Field;
use mpz_poly_proof_core::ExtensionField;

/// Fixed-length container of `T` slots holding one component of a
/// logical wire — its cleartext, its IT-MAC, or its key.
///
/// A wire may span multiple slots when its encoding takes more than one field
/// element.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bundle<T>(Vec<T>);

impl<T> Bundle<T> {
    /// Wrap an existing `Vec<T>` as a bundle.
    pub fn new(slots: Vec<T>) -> Self {
        Self(slots)
    }

    /// Unwrap into the underlying `Vec<T>`.
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    /// Borrow as a slice.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T> From<Vec<T>> for Bundle<T> {
    fn from(v: Vec<T>) -> Self {
        Self(v)
    }
}

/// Singleton bundle: a single value lifted into a length-1 bundle.
impl<T> From<T> for Bundle<T> {
    fn from(v: T) -> Self {
        Self(vec![v])
    }
}

impl<T> FromIterator<T> for Bundle<T> {
    fn from_iter<I: IntoIterator<Item = T>>(it: I) -> Self {
        Self(it.into_iter().collect())
    }
}

impl<T> std::ops::Deref for Bundle<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T> IntoIterator for Bundle<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Bundle<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Prover-side authenticated wire.
///
/// Value and IT-MAC bundles are parallel.
#[derive(Clone)]
pub struct ProverWire<S, F> {
    value: Bundle<S>,
    mac: Bundle<F>,
}

impl<S, F> ProverWire<S, F>
where
    F: Field,
{
    /// Pair a value-side bundle with its mac-side bundle.
    ///
    /// # Panics
    ///
    /// Panics if `value` and `mac` have different lengths, or if
    /// either is empty.
    pub fn new(value: Bundle<S>, mac: Bundle<F>) -> Self {
        assert_eq!(
            value.len(),
            mac.len(),
            "ProverWire: value/mac length mismatch ({} vs {})",
            value.len(),
            mac.len(),
        );
        assert!(
            !value.is_empty(),
            "ProverWire: zero-slot wires are not allowed",
        );
        Self { value, mac }
    }

    /// Construct a public-constant wire.
    pub fn constant(value: impl Into<Bundle<S>>) -> Self {
        let value = value.into();
        let mac = Bundle::from(vec![F::zero(); value.len()]);
        Self::new(value, mac)
    }

    /// Cleartext value of the wire.
    pub fn value(&self) -> &Bundle<S> {
        &self.value
    }

    /// IT-MAC of the wire.
    pub fn mac(&self) -> &Bundle<F> {
        &self.mac
    }

    /// Number of slots in this wire.
    pub fn len(&self) -> usize {
        self.value.len()
    }
}

/// Verifier-side authenticated wire.
#[derive(Clone)]
pub struct VerifierWire<F> {
    /// Verifier-side keys.
    pub key: Bundle<F>,
}

impl<F: Field> VerifierWire<F> {
    /// Creates a new wire.
    pub fn new(key: Bundle<F>) -> Self {
        Self { key }
    }

    /// Construct the verifier-side wire for a public-constant value.
    pub fn constant<S>(value: &[S], delta: F) -> Self
    where
        S: Field,
        F: ExtensionField<S>,
    {
        // Convention: when the prover constructs a public-constant wire
        // (MAC=0), the verifier holds `K = −Δ · v.embed()` per slot.
        let key = value.iter().map(|v| -(F::embed(*v) * delta)).collect();
        Self { key }
    }

    /// Number of slots in this wire.
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Pack into a [`PackedVerifierWire`] over the chosen subfield `S`.
    pub(crate) fn pack<S>(&self) -> PackedVerifierWire<F>
    where
        S: Field,
        F: ExtensionField<S>,
    {
        PackedVerifierWire::pack::<S>(&self.key)
    }
}

/// Build a [`VerifierWire`] directly from anything convertible to a
/// [`Bundle<F>`].
impl<F, T> From<T> for VerifierWire<F>
where
    T: Into<Bundle<F>>,
{
    fn from(keys: T) -> Self {
        Self { key: keys.into() }
    }
}

/// Prover-side packed wire.
#[derive(Copy, Clone)]
pub(crate) struct PackedProverWire<F> {
    pub value: F,
    pub mac: F,
}

/// Verifier-side packed wire.
#[derive(Copy, Clone)]
pub(crate) struct PackedVerifierWire<F> {
    pub key: F,
}

/// Pack a `VerifierWire` into a `PackedVerifierWire`.
///
/// The caller is responsible for ensuring that the input wire's
/// key bundle can be packed into the extension field `F` without
/// information loss — i.e. that its slot count fits within `F`'s
/// extension degree over `S`.
impl<F> PackedVerifierWire<F>
where
    F: Field,
{
    /// Pack a raw key slice into a `PackedVerifierWire`.
    pub(crate) fn pack<S>(keys: &[F]) -> Self
    where
        S: Field,
        F: ExtensionField<S>,
    {
        Self {
            key: pack_extension::<S, F>(keys),
        }
    }
}

/// Pack a `ProverWire` into a `PackedWire`.
///
/// The caller is responsible for ensuring that the input wire's
/// value bundle can be packed into the extension field `F` without
/// information loss — i.e. that its slot count fits within `F`'s
/// extension degree over `S`.
impl<S, F> From<&ProverWire<S, F>> for PackedProverWire<F>
where
    S: Field,
    F: ExtensionField<S>,
{
    fn from(input: &ProverWire<S, F>) -> Self {
        let value_bundle = input.value();
        // Σ embed(value[i]) · α^i — canonical subfield→extension lift
        // against the leading slice of the monomial basis.
        let value = <F as ExtensionField<S>>::inner_product_subfield(
            value_bundle,
            &<F as ExtensionField<S>>::MONOMIAL_BASIS[..value_bundle.len()],
        );
        let mac = pack_extension::<S, F>(input.mac());
        Self { value, mac }
    }
}

/// Pack a bundle of `F` elements into a single `F` element by taking
/// a linear combination against the leading slice of `F`'s canonical
/// monomial basis over `S`.
///
/// The caller is responsible for ensuring `values.len()` fits within
/// the basis size.
pub(crate) fn pack_extension<S, F>(values: &[F]) -> F
where
    S: Field,
    F: ExtensionField<S>,
{
    let basis = &<F as ExtensionField<S>>::MONOMIAL_BASIS[..values.len()];
    values
        .iter()
        .zip(basis.iter())
        .fold(F::zero(), |acc, (&v, &b)| acc + v * b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_fields::{Field, gf2::Gf2, gf2_64::Gf2_64};

    // -----------------------------------------------------------------------
    // Bundle: constructors + round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_new_and_into_inner_round_trip() {
        let v = vec![1u32, 2, 3, 4];
        let bundle = Bundle::new(v.clone());
        assert_eq!(bundle.into_inner(), v);
    }

    #[test]
    fn bundle_from_vec_wraps_full_vec() {
        let bundle: Bundle<u32> = vec![10, 20, 30].into();
        assert_eq!(bundle.len(), 3);
        assert_eq!(*bundle, [10, 20, 30]);
    }

    #[test]
    fn bundle_from_singleton_lifts_to_length_one() {
        // `From<T> for Bundle<T>` — single value → length-1 bundle.
        // Critical for prime-field call sites that use `.into()`
        // without an explicit `vec![...]` wrap.
        let bundle: Bundle<u32> = 42u32.into();
        assert_eq!(bundle.len(), 1);
        assert_eq!(bundle[0], 42);
    }

    #[test]
    fn bundle_from_iter_collects() {
        let bundle: Bundle<u32> = (0..5).collect();
        assert_eq!(*bundle, [0, 1, 2, 3, 4]);
    }

    // -----------------------------------------------------------------------
    // Bundle: Deref + IntoIterator
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_deref_exposes_slice_methods() {
        let bundle: Bundle<u32> = vec![7, 8, 9].into();
        // Methods that come from `&[T]` via Deref:
        assert_eq!(bundle.len(), 3);
        assert!(!bundle.is_empty());
        assert_eq!(bundle.first(), Some(&7));
        assert_eq!(bundle.iter().sum::<u32>(), 24);
        // Indexing:
        assert_eq!(bundle[1], 8);
        // as_slice() helper:
        assert_eq!(bundle.as_slice(), &[7, 8, 9]);
    }

    #[test]
    fn bundle_owned_into_iter_consumes() {
        let bundle: Bundle<u32> = vec![1, 2, 3].into();
        let collected: Vec<u32> = bundle.into_iter().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn bundle_ref_into_iter_borrows() {
        let bundle: Bundle<u32> = vec![1, 2, 3].into();
        // `for x in &bundle` works.
        let collected: Vec<u32> = (&bundle).into_iter().copied().collect();
        assert_eq!(collected, vec![1, 2, 3]);
        // bundle is still usable.
        assert_eq!(bundle.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Bundle: Ord + Eq for BTreeMap key use
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_ord_lexicographic() {
        let a: Bundle<u32> = vec![1, 2, 3].into();
        let b: Bundle<u32> = vec![1, 2, 4].into();
        let c: Bundle<u32> = vec![1, 2, 3].into();
        assert!(a < b, "shorter-first byte should sort earlier");
        assert_eq!(a, c, "elementwise equality");
        assert_ne!(a, b);
    }

    #[test]
    fn bundle_works_as_btreemap_key() {
        // Smoke: Ord + Eq derives are wired up so Bundle<S> can key
        // a BTreeMap. Used by the shadow tables in every protocol.
        use std::collections::BTreeMap;
        let mut m: BTreeMap<Bundle<u32>, &'static str> = BTreeMap::new();
        m.insert(vec![1, 2].into(), "ab");
        m.insert(vec![3].into(), "c");
        assert_eq!(m.get(&Bundle::<u32>::from(vec![1, 2])), Some(&"ab"));
        assert_eq!(m.len(), 2);
    }

    // -----------------------------------------------------------------------
    // InputWire::constant
    // -----------------------------------------------------------------------

    #[test]
    fn input_wire_constant_vec_zeroes_mac() {
        // `Vec<S>` source → bundle of same length, mac is all zero.
        let value = vec![Gf2(true), Gf2(false), Gf2(true)];
        let wire: ProverWire<Gf2, Gf2_64> = ProverWire::constant(value.clone());
        assert_eq!(wire.value.len(), 3);
        assert_eq!(wire.mac.len(), 3);
        assert_eq!(*wire.value, value[..]);
        for m in wire.mac.iter() {
            assert_eq!(*m, Gf2_64::zero(), "mac slot must be zero for constant");
        }
    }

    #[test]
    fn input_wire_constant_singleton() {
        // `S` source → length-1 wire, mac = [0].
        let wire: ProverWire<Gf2, Gf2_64> = ProverWire::constant(Gf2(true));
        assert_eq!(wire.value.len(), 1);
        assert_eq!(wire.mac.len(), 1);
        assert_eq!(wire.value[0], Gf2(true));
        assert_eq!(wire.mac[0], Gf2_64::zero());
    }

    #[test]
    fn input_wire_constant_bundle_passes_through() {
        // `Bundle<S>` source → identity on value side, mac = zeros.
        let value: Bundle<Gf2> = vec![Gf2(false), Gf2(true)].into();
        let wire: ProverWire<Gf2, Gf2_64> = ProverWire::constant(value.clone());
        assert_eq!(*wire.value, *value);
        assert!(wire.mac.iter().all(|&m| m == Gf2_64::zero()));
    }

    // -----------------------------------------------------------------------
    // VerifierWire::constant
    // -----------------------------------------------------------------------

    #[test]
    fn verifier_wire_constant_negates_scalar_mul_per_slot() {
        // For each slot `v`, key = −v.scalar_mul(delta).
        //   Gf2(false) → 0
        //   Gf2(true)  → −delta  (= delta in char-2 Gf2_64)
        let delta = Gf2_64(0xdead_beef_cafe_babe);
        let value = [Gf2(true), Gf2(false), Gf2(true)];
        let wire: VerifierWire<Gf2_64> = VerifierWire::constant(&value, delta);
        assert_eq!(wire.key.len(), 3);
        assert_eq!(wire.key[0], -delta);
        assert_eq!(wire.key[1], Gf2_64::zero());
        assert_eq!(wire.key[2], -delta);
        // Char-2 cross-check: -delta == delta in Gf2_64.
        assert_eq!(-delta, delta);
    }

    #[test]
    fn verifier_wire_constant_empty_input_yields_empty_key() {
        let delta = Gf2_64(0x1234);
        let wire: VerifierWire<Gf2_64> = VerifierWire::constant::<Gf2>(&[], delta);
        assert_eq!(wire.key.len(), 0);
    }
}
