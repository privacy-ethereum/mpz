//! Clock component layer for the RAM protocol.
//!
//! Per access, the RAM protocol must produce an authenticated wire
//! for `delta = "current_clock − t_old"` and prove `delta ∈ {1..T}`
//! via a set membership lookup. The specific encoding of clock
//! values and the meaning of "subtraction" depend on the field
//! arithmetic: prime fields use additive subtraction, char-2 fields
//! use multiplicative encoding.

use itybity::{FromBitIterator, ToBits};
use mpz_fields::{Field, gf2::Gf2};
use mpz_poly_proof_core::ExtensionField;

use crate::{
    gf2n::{GfMulMatrix, UnsupportedDegree, field_constants, gf2n_mul_mod},
    strategy::{Char2, IntegerLike},
    wire::{Bundle, ProverWire, VerifierWire},
};

/// Clock's running state and metadata.
pub trait Clock<S> {
    /// Wire length of the clock encoding.
    fn l_clock(&self) -> usize;

    /// Current clock cleartext.
    fn current_clock(&self) -> &Bundle<S>;

    /// Advance the internal clock state by one step. Subsequent
    /// calls to `current_clock` reflect the new step.
    fn next_clock(&mut self);

    /// The valid set of delta values for the protocol.
    fn valid_deltas(&self) -> Vec<Bundle<S>>;
}

/// Prover-side clock.
pub trait ProverClock<S, F>: Clock<S>
where
    S: Field,
    F: ExtensionField<S>,
{
    /// Compute the authenticated `delta` wire.
    fn compute_delta(&self, t_old: &ProverWire<S, F>) -> ProverWire<S, F>;
}

/// Verifier-side clock.
pub trait VerifierClock<S, F>: Clock<S>
where
    S: Field,
    F: ExtensionField<S>,
{
    /// Compute the authenticated `delta` wire.
    ///
    /// # Arguments
    ///
    /// * `t_old` — wire for `t_old`.
    /// * `correlation` — global correlation key.
    fn compute_delta(&self, t_old: &VerifierWire<F>, correlation: F) -> VerifierWire<F>;
}

// ---------------------------------------------------------------------------
// AdditiveClock
// ---------------------------------------------------------------------------

/// Additive `delta = current_clock − t_old` strategy for prime fields.
///
/// Clock value `i` is encoded as the field element `i` directly
/// (`S::zero() + S::one() · i`). The valid delta set is `{1, 2, …, T}` —
/// positive integers, since prime-field subtraction matches integer
/// subtraction for values in this range.
pub struct AdditiveClock<S> {
    total_accesses: usize,
    /// Running clock value.
    clock: S,
    /// Length-1 bundle wrapper around `clock`
    //
    // Kept in sync so we can return a borrowed `&Bundle<S>` without per-call allocation.
    current_clock: Bundle<S>,
}

impl<S> AdditiveClock<S>
where
    S: Field,
{
    /// Construct a strategy for `total_accesses` total accesses.
    ///
    /// # Panics
    ///
    /// Panics if `total_accesses == 0`.
    pub fn new(total_accesses: usize) -> Result<Self, AdditiveClockError> {
        // TODO: compare to (Field::ORDER - 1) / 2 (ORDER not exposed in mpz atm).
        if (total_accesses.ilog2() as usize) >= S::BIT_SIZE - 2 {
            return Err(AdditiveClockError::TooManyAccesses { total_accesses });
        }
        Ok(Self {
            total_accesses,
            clock: S::zero(),
            current_clock: S::zero().into(),
        })
    }
}

impl<S> Clock<S> for AdditiveClock<S>
where
    S: Field + IntegerLike,
{
    fn l_clock(&self) -> usize {
        1
    }

    fn current_clock(&self) -> &Bundle<S> {
        &self.current_clock
    }

    fn next_clock(&mut self) {
        self.clock = self.clock + S::one();
        self.current_clock = self.clock.into();
    }

    fn valid_deltas(&self) -> Vec<Bundle<S>> {
        // {1, 2, …, T} as length-1 bundles.
        let mut out = Vec::with_capacity(self.total_accesses);
        let mut y = S::zero();
        for _ in 0..self.total_accesses {
            y = y + S::one();
            out.push(y.into());
        }
        out
    }
}

impl<S, F> ProverClock<S, F> for AdditiveClock<S>
where
    S: Field + IntegerLike,
    F: ExtensionField<S>,
{
    fn compute_delta(&self, t_old: &ProverWire<S, F>) -> ProverWire<S, F> {
        assert_eq!(t_old.len(), 1);

        // delta = current_clock − t_old.
        // Subtracting a public constant from an authenticated wire:
        //   v_delta = c − v        (cleartext op)
        //   M_delta = −M_v         (MAC sign-flip; satisfies
        //                            M_delta = K_delta + Δ·v_delta.embed
        //                            with K_delta = −K_v − Δ·c.embed)
        ProverWire::new(
            (self.clock - t_old.value()[0]).into(),
            (-t_old.mac()[0]).into(),
        )
    }
}

impl<S, F> VerifierClock<S, F> for AdditiveClock<S>
where
    S: Field + IntegerLike,
    F: ExtensionField<S>,
{
    fn compute_delta(&self, t_old: &VerifierWire<F>, correlation: F) -> VerifierWire<F> {
        assert_eq!(t_old.len(), 1);
        // K_delta = −K_t_old − Δ · current_clock.embed().
        VerifierWire::new((-t_old.key[0] - correlation * F::embed(self.clock)).into())
    }
}

/// Construction error for [`AdditiveClock`].
#[derive(Debug, thiserror::Error)]
pub enum AdditiveClockError {
    /// Too many accesses.
    #[error("total_accesses {total_accesses} exceeds field bound")]
    TooManyAccesses {
        /// Requested total access count.
        total_accesses: usize,
    },
}

// ---------------------------------------------------------------------------
// MultiplicativeClock
// ---------------------------------------------------------------------------

/// Clock whose state advances by **multiplication** in `GF(2^N)`:
/// at tick `i` the state holds `g^i` for a fixed primitive `g`, and
/// `next_clock` is the single field op `state ← g · state`.
///
/// To check that the prover's claimed `t_old = g^j` corresponds to a
/// past clock, the strategy computes
/// `delta = g^{-current_clock} · t_old = g^{j-current_clock}`. The
/// valid set is `{g^{-1}, g^{-2}, …, g^{-T}}` — i.e. the inverse
/// powers of `g`, one per past tick.
///
/// We maintain `g^{-current_clock}` as a running scalar rather than computing
/// `t_old^{-1}` per access, which would require a more expensive full field
/// inversion (e.g. extended Euclidean).
pub struct MultiplicativeClock {
    total_accesses: usize,
    /// Extension degree of the clock's working field `GF(2^n)`.
    n: usize,
    /// Irreducible polynomial defining `GF(2^n)`, with bit `n` set.
    poly: u64,
    /// Primitive element, i.e. the generator.
    g: u64,
    /// Multiplicative inverse of `g`.
    g_inv: u64,

    /// Running positive clock = `g^current_clock`, in bit-pattern
    /// `Bundle<Gf2>` form.
    pos_clock_bits: Bundle<Gf2>,

    /// Running positive clock as a `u64` bit pattern. Same value as
    /// `pos_clock_bits`.
    pos_clock_u64: u64,

    /// Running negative clock = `g^{-current_clock}`, as a `u64`.
    /// Each `next_clock` advances by `· g_inv`.
    neg_clock_u64: u64,
}

impl MultiplicativeClock {
    /// Construct a strategy for `total_accesses` total accesses.
    ///
    /// # Panics
    ///
    /// Panics if `total_accesses` exceeds the maximum supported.
    pub fn new(total_accesses: usize) -> Result<Self, MulClockError> {
        let n = smallest_valid_n(total_accesses)?;
        let c = field_constants(n).expect("smallest_valid_n returns a supported n");

        // Running counters initialized at the anchor (g^0 = 1).
        let mut pos_clock_bits = vec![Gf2::ZERO; n];
        pos_clock_bits[0] = Gf2::ONE;

        Ok(Self {
            total_accesses,
            n,
            poly: c.poly,
            g: c.generator,
            g_inv: c.g_inv,
            pos_clock_bits: pos_clock_bits.into(),
            pos_clock_u64: 1,
            neg_clock_u64: 1,
        })
    }
}

impl Clock<Gf2> for MultiplicativeClock {
    fn l_clock(&self) -> usize {
        self.n
    }

    fn current_clock(&self) -> &Bundle<Gf2> {
        &self.pos_clock_bits
    }

    fn next_clock(&mut self) {
        // Advance pos by *g and neg by *g_inv.
        self.pos_clock_u64 = gf2n_mul_mod(self.pos_clock_u64, self.g, self.poly, self.n);
        self.neg_clock_u64 = gf2n_mul_mod(self.neg_clock_u64, self.g_inv, self.poly, self.n);
        // Keep the bundle form in sync for `clock_encoded` borrowers.
        self.pos_clock_bits =
            Vec::<Gf2>::from_lsb0_iter(self.pos_clock_u64.iter_lsb0().take(self.n)).into();
    }

    fn valid_deltas(&self) -> Vec<Bundle<Gf2>> {
        // g^{-1}, g^{-2}, …, g^{-T}} via running multiplication by g_inv.
        let mut y = 1u64;
        let mut out = Vec::with_capacity(self.total_accesses);
        for _ in 0..self.total_accesses {
            y = gf2n_mul_mod(y, self.g_inv, self.poly, self.n);
            out.push(Vec::<Gf2>::from_lsb0_iter(y.iter_lsb0().take(self.n)).into());
        }
        out
    }
}

impl<F> ProverClock<Gf2, F> for MultiplicativeClock
where
    F: Char2 + ExtensionField<Gf2>,
{
    fn compute_delta(&self, t_old: &ProverWire<Gf2, F>) -> ProverWire<Gf2, F> {
        assert_eq!(t_old.len(), self.n);

        // Build the multiply-by-`g^{-current_clock}` matrix from the
        // running negative counter, then apply to `t_old = g^j`.
        // Result is `g^{j-current_clock}` — a negative power of `g`.
        let matrix = GfMulMatrix::new(self.poly, self.neg_clock_u64, self.n);
        let next_value = matrix.apply(t_old.value());
        let next_mac = matrix.apply_lifted(t_old.mac());
        ProverWire::new(next_value.into(), next_mac.into())
    }
}

impl<F> VerifierClock<Gf2, F> for MultiplicativeClock
where
    F: Char2 + ExtensionField<Gf2>,
{
    fn compute_delta(&self, t_old: &VerifierWire<F>, _correlation: F) -> VerifierWire<F> {
        assert_eq!(t_old.len(), self.n);

        // Build the multiply-by-`g^{-current_clock}` matrix from the
        // running negative counter, then apply to `t_old = g^j`.
        // Result is `g^{j-current_clock}` — a negative power of `g`.
        let matrix = GfMulMatrix::new(self.poly, self.neg_clock_u64, self.n);
        VerifierWire::new(matrix.apply_lifted(&t_old.key).into())
    }
}

/// Construction error for [`MultiplicativeClock`].
#[derive(Debug, thiserror::Error)]
pub enum MulClockError {
    /// Wire length `n` is not supported.
    #[error("unsupported bundle size: {0}")]
    UnsupportedDegree(#[from] UnsupportedDegree),

    /// `total_accesses` size is not supported.
    #[error("total_accesses {0} too large")]
    TooManyAccesses(usize),
}

/// Smallest supported wire length `n` whose multiplicative group
/// of order `2^n − 1` satisfies `≥ 2·total_accesses + 1`.
fn smallest_valid_n(total_accesses: usize) -> Result<usize, MulClockError> {
    let needed = 2u64
        .checked_mul(total_accesses as u64)
        .and_then(|x| x.checked_add(1))
        .ok_or(MulClockError::TooManyAccesses(total_accesses))?;
    for n in 8..=26 {
        if field_constants(n).expect("n in 8..=26").group_order >= needed {
            return Ok(n);
        }
    }
    Err(MulClockError::TooManyAccesses(total_accesses))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{bits, pow_mod, prover_wire};
    use mpz_fields::{gf2_64::Gf2_64, p256::P256};
    use mpz_vole_core::test::assert_vole;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    // Until mpz-fields offers a prime subfield carrying an extension
    // field (rather than only the gf2 family), we work around it by
    // marking Gf2_64 IntegerLike — just enough to instantiate
    // AdditiveClock::compute_delta and test that the clock increments
    // correctly (0 → 1).
    impl IntegerLike for Gf2_64 {}

    /// The field element equal to integer `k` (i.e. `1` summed `k`
    /// times) — independent of the field's internal representation.
    fn ones<S: Field>(k: u64) -> S {
        (0..k).fold(S::zero(), |acc, _| acc + S::one())
    }

    // -----------------------------------------------------------------------
    // MultiplicativeClock
    // -----------------------------------------------------------------------

    /// A fresh clock anchors both running counters at `g^0 = 1`.
    #[test]
    fn mul_clock_starts_at_anchor() {
        let c = MultiplicativeClock::new(100).expect("new");
        assert_eq!(c.pos_clock_u64, 1);
        assert_eq!(c.neg_clock_u64, 1);
        assert_eq!(c.current_clock().as_slice(), bits(1, c.n).as_slice());
    }

    /// The positive and negative counters stay multiplicative
    /// inverses at every tick: `g^i · g^{-i} = 1`.
    #[test]
    fn mul_clock_counters_are_inverses() {
        let mut c = MultiplicativeClock::new(100).expect("new");
        for _ in 0..50 {
            c.next_clock();
            assert_eq!(
                gf2n_mul_mod(c.pos_clock_u64, c.neg_clock_u64, c.poly, c.n),
                1,
                "pos · neg must be 1",
            );
        }
    }

    /// After `k` ticks the counters hold `g^k` / `g^{-k}`, and the
    /// bundle bit-form stays in sync with the u64.
    #[test]
    fn mul_clock_tracks_g_powers() {
        let mut c = MultiplicativeClock::new(100).expect("new");
        for k in 1..=50u64 {
            c.next_clock();
            let pos = pow_mod(c.g, k, c.poly, c.n);
            let neg = pow_mod(c.g_inv, k, c.poly, c.n);
            assert_eq!(c.pos_clock_u64, pos, "g^{k}");
            assert_eq!(c.neg_clock_u64, neg, "g^-{k}");
            assert_eq!(c.current_clock().as_slice(), bits(pos, c.n).as_slice());
        }
    }

    /// `valid_deltas` is exactly `[g^{-1}, …, g^{-T}]`.
    #[test]
    fn mul_clock_valid_deltas() {
        let c = MultiplicativeClock::new(20).expect("new");
        let deltas = c.valid_deltas();
        assert_eq!(deltas.len(), 20);
        for (k, d) in deltas.iter().enumerate() {
            let expected = pow_mod(c.g_inv, k as u64 + 1, c.poly, c.n);
            assert_eq!(d.as_slice(), bits(expected, c.n).as_slice(), "g^-{}", k + 1);
        }
    }

    /// `compute_delta` yields `g^{j-current} · t_old`.
    /// - `t_old = current_clock` (j = current) → `g^0 = 1`.
    /// - `t_old = g^j` for a past `j` → the matching `valid_deltas` entry.
    #[test]
    fn mul_clock_compute_delta_cleartext() {
        let mut clock = MultiplicativeClock::new(50).expect("new");
        for _ in 0..10 {
            clock.next_clock(); // current = 10
        }

        // t_old at the current tick → delta = 1.
        let t_now = prover_wire::<Gf2, Gf2_64>(clock.current_clock().to_vec());
        let d_now =
            <MultiplicativeClock as ProverClock<Gf2, Gf2_64>>::compute_delta(&clock, &t_now);
        assert_eq!(d_now.value().as_slice(), bits(1, clock.n).as_slice());

        // t_old = g^3, current = 10 → delta = g^{-7} = valid_deltas[6].
        let g3 = pow_mod(clock.g, 3, clock.poly, clock.n);
        let t_past = prover_wire::<Gf2, Gf2_64>(bits(g3, clock.n));
        let d_past =
            <MultiplicativeClock as ProverClock<Gf2, Gf2_64>>::compute_delta(&clock, &t_past);
        let expected = pow_mod(clock.g_inv, 7, clock.poly, clock.n);
        assert_eq!(
            d_past.value().as_slice(),
            bits(expected, clock.n).as_slice()
        );
        assert_eq!(
            d_past.value().as_slice(),
            clock.valid_deltas()[6].as_slice(),
            "past delta must be a valid-set member",
        );
    }

    /// Given an authenticated `t_old` (`M = K + Δ·embed(v)` per bit),
    /// the prover's and verifier's delta wires satisfy the same IT-MAC
    /// invariant — i.e. `apply` (value) and `apply_lifted` (MAC/key)
    /// stay consistent through the matrix.
    #[test]
    fn mul_clock_compute_delta_preserves_itmac() {
        let mut rng = StdRng::seed_from_u64(0xc10c);
        let mut clock = MultiplicativeClock::new(50).expect("new");
        for _ in 0..8 {
            clock.next_clock();
        }

        let corr: Gf2_64 = rng.random();
        let v = bits(pow_mod(clock.g, 5, clock.poly, clock.n), clock.n);
        let keys: Vec<Gf2_64> = (0..clock.n).map(|_| rng.random()).collect();
        let macs: Vec<Gf2_64> = v
            .iter()
            .zip(&keys)
            .map(|(vi, ki)| *ki + corr * <Gf2_64 as ExtensionField<Gf2>>::embed(*vi))
            .collect();

        let p_t = ProverWire::new(Bundle::new(v), Bundle::new(macs));
        let v_t = VerifierWire::new(Bundle::new(keys));

        let p_d = <MultiplicativeClock as ProverClock<Gf2, Gf2_64>>::compute_delta(&clock, &p_t);
        let v_d =
            <MultiplicativeClock as VerifierClock<Gf2, Gf2_64>>::compute_delta(&clock, &v_t, corr);

        assert_vole(
            corr,
            v_d.key.as_slice(),
            p_d.value().as_slice(),
            p_d.mac().as_slice(),
        );
    }

    // -----------------------------------------------------------------------
    // AdditiveClock
    // -----------------------------------------------------------------------

    /// The `Clock` surface over a prime field — single-slot encoding,
    /// clock starts at 0 and increments by 1, valid set is `[1..=T]`.
    #[test]
    fn additive_clock_surface() {
        let mut clock = AdditiveClock::<P256>::new(5).expect("new");
        assert_eq!(clock.l_clock(), 1);
        assert_eq!(clock.current_clock().as_slice(), [P256::zero()].as_slice());

        for k in 1..=5u64 {
            clock.next_clock();
            assert_eq!(
                clock.current_clock().as_slice(),
                [ones::<P256>(k)].as_slice()
            );
        }

        let deltas = clock.valid_deltas();
        assert_eq!(deltas.len(), 5);
        for (k, d) in deltas.iter().enumerate() {
            assert_eq!(d.as_slice(), [ones::<P256>(k as u64 + 1)].as_slice());
        }
    }

    /// `new(0)` panics (documented; `0usize.ilog2()` is undefined).
    #[test]
    #[should_panic]
    fn additive_clock_new_zero_panics() {
        let _ = AdditiveClock::<P256>::new(0);
    }

    /// With the clock parked at 1, the additive `compute_delta` MAC
    /// algebra — `v_delta = c − v`, `M_delta = −M_v`,
    /// `K_delta = −K_v − Δ·embed(c)` — yields a delta wire that
    /// satisfies the IT-MAC invariant. Field-generic algebra, so the
    /// `Gf2_64` stand-in is sound (see the module note). The multi-step
    /// increment semantics are covered by `additive_clock_surface` over
    /// the real `P256`.
    #[test]
    fn additive_clock_compute_delta_preserves_itmac() {
        let mut rng = StdRng::seed_from_u64(0xadd1);
        let mut clock = AdditiveClock::<Gf2_64>::new(3).expect("new");
        clock.next_clock(); // 0 → 1: the one step that agrees in any field

        let corr: Gf2_64 = rng.random();
        let v: Gf2_64 = rng.random();
        let key: Gf2_64 = rng.random();
        let mac = key + corr * <Gf2_64 as ExtensionField<Gf2_64>>::embed(v);

        let p_t = ProverWire::new(Bundle::new(vec![v]), Bundle::new(vec![mac]));
        let v_t = VerifierWire::new(Bundle::new(vec![key]));

        let p_d =
            <AdditiveClock<Gf2_64> as ProverClock<Gf2_64, Gf2_64>>::compute_delta(&clock, &p_t);
        let v_d = <AdditiveClock<Gf2_64> as VerifierClock<Gf2_64, Gf2_64>>::compute_delta(
            &clock, &v_t, corr,
        );

        // Cleartext: delta = current_clock − v.
        let c = clock.current_clock()[0];
        assert_eq!(p_d.value()[0], c - v);
        // IT-MAC invariant carries to the delta wire.
        assert_vole(corr, &[v_d.key[0]], &[p_d.value()[0]], &[p_d.mac()[0]]);
    }
}
