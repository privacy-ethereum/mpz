//! Test utilities shared across the end-to-end protocol tests in
//! this crate.

use itybity::{FromBitIterator, ToBits};
use mpz_common::future::Output;
use mpz_fields::{ExtensionField, Field, gf2::Gf2, gf2_64::Gf2_64};
use mpz_vole_core::{
    DerandVOLEReceiver, DerandVOLESender, RVOLEReceiver, RVOLESender, VOLEReceiver, VoleAdjustment,
    ideal::{
        rvole::{IdealRVOLEReceiver, IdealRVOLESender, ideal_rvole},
        vole::{FlushMsg, ideal_vole},
    },
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rangeset::set::RangeSet;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    gf2n::gf2n_mul_mod,
    ram::mux_mul::{MuxMulProver, MuxMulVerifier},
    strategy::{Char2Strategy, FieldStrategy, IntegerLike},
    wire::{Bundle, ProverWire, VerifierWire},
};

// Test-only opt-in: `P256` is integer-like for protocol purposes, but
// the production crate ships no prime-field strategy wired up, so this
// marker lives here for the test harness. Drop once a production impl
// exists.
impl IntegerLike for mpz_fields::p256::P256 {}

/// Commit one cleartext bundle via an ideal chosen-VOLE session and
/// return the matching prover/verifier wires.
pub fn commit_value<W, E>(
    value: Vec<W>,
    delta: E,
    rng: &mut impl Rng,
    transcript: &mut blake3::Hasher,
) -> (ProverWire<W, E>, VerifierWire<E>)
where
    W: Field,
    E: ExtensionField<W> + serde::Serialize,
{
    let width = value.len();
    let seed: u64 = rng.random();

    let (mut sender, mut receiver) = ideal_vole::<W, E>(seed, delta);
    <_ as RVOLESender<E>>::alloc(&mut sender, width).expect("sender alloc");
    <_ as VOLEReceiver<W, E>>::alloc(&mut receiver, width).expect("receiver alloc");

    let mut fut = receiver.queue_recv_vole(&value).expect("queue");

    let flush = sender.flush().expect("flush must produce a message");
    absorb_vole_flush(transcript, &flush);
    receiver.flush(flush).expect("receiver flush");

    let macs = fut
        .try_recv()
        .expect("future must not cancel")
        .expect("future must resolve after flush")
        .macs;
    let keys = sender.try_send_vole(width).expect("sender keys").keys;

    (
        ProverWire::new(Bundle::new(value), Bundle::new(macs)),
        VerifierWire::new(Bundle::new(keys)),
    )
}

/// Commit an `N`-slot tuple of cleartext bundles.
pub fn commit_tuple<W, E, const N: usize>(
    values: [Vec<W>; N],
    delta: E,
    rng: &mut impl Rng,
    transcript: &mut blake3::Hasher,
) -> [(ProverWire<W, E>, VerifierWire<E>); N]
where
    W: Field,
    E: ExtensionField<W> + serde::Serialize,
{
    values.map(|v| commit_value(v, delta, rng, transcript))
}

/// Commit a sequence of `N`-tuples against a *fresh* shared
/// transcript and return the per-tuple wire arrays alongside the
/// post-commit transcript both sides start from.
pub fn commit_accesses<W, E, const N: usize>(
    accesses: Vec<[Vec<W>; N]>,
    delta: E,
    rng: &mut impl Rng,
) -> (
    Vec<[(ProverWire<W, E>, VerifierWire<E>); N]>,
    blake3::Hasher,
)
where
    W: Field,
    E: ExtensionField<W> + serde::Serialize,
{
    let mut transcript = blake3::Hasher::new();
    let commits = accesses
        .into_iter()
        .map(|tuple| commit_tuple::<W, E, N>(tuple, delta, rng, &mut transcript))
        .collect();
    (commits, transcript)
}

/// Absorb the bytes of an ideal-VOLE [`FlushMsg`] into a transcript.
fn absorb_vole_flush<E: Field + serde::Serialize>(
    transcript: &mut blake3::Hasher,
    msg: &FlushMsg<E>,
) {
    transcript.update(b"two-shuffles::test::ideal-vole-flush");
    transcript.update(&bcs::to_bytes(msg).expect("serialize"));
}

/// An unauthenticated prover wire.
pub fn prover_wire<W, E: Field>(values: Vec<W>) -> ProverWire<W, E> {
    let macs = vec![E::zero(); values.len()];
    ProverWire::new(Bundle::new(values), Bundle::new(macs))
}

/// A verifier wire built directly from its key slots.
pub fn verifier_wire<E: Field>(keys: Vec<E>) -> VerifierWire<E> {
    VerifierWire::new(Bundle::new(keys))
}

/// A zeroed VOLE adjustment of the given slot width.
pub fn vole_adjustment<E: Field>(width: usize) -> VoleAdjustment<E> {
    VoleAdjustment {
        diffs: vec![E::zero(); width],
    }
}

/// Build a paired, `Allocated` mux-mul prover/verifier over
/// `Gf2`/`Gf2_64`, sharing one Δ and one mul-VOLE pool sized for
/// `num_slots` product slots. `verifier_bool` selects the verifier's
/// booleanness-check flag. Returns `(prover, verifier, delta)`.
pub fn mux_mul_pair(
    num_slots: usize,
    verifier_bool: bool,
) -> (
    MuxMulProver<impl RVOLEReceiver<Gf2, Gf2_64>, impl RVOLEReceiver<Gf2, Gf2_64>, Gf2, Gf2_64>,
    MuxMulVerifier<impl RVOLESender<Gf2_64>, impl RVOLESender<Gf2_64>, Gf2, Gf2_64>,
    Gf2_64,
) {
    let mut rng = StdRng::seed_from_u64(0x2b2b);
    let delta: Gf2_64 = rng.random();

    let vope_count = <Gf2_64 as ExtensionField<Gf2>>::MONOMIAL_BASIS.len();
    let (mut vope_s, mut vope_r) = ideal_rvole::<Gf2, Gf2_64>(rng.random(), delta);
    vope_s.pregenerate(vope_count);
    vope_r
        .pregenerate(vope_count, delta)
        .expect("vope r pregenerate");

    // One shared mul pool: same seed + Δ on both sides so the prover's
    // product MACs and the verifier's product keys pair up.
    let mul_seed: u64 = rng.random();
    let (mut mul_s, mut mul_r) = ideal_rvole::<Gf2, Gf2_64>(mul_seed, delta);
    mul_s.pregenerate(num_slots);
    mul_r
        .pregenerate(num_slots, delta)
        .expect("mul r pregenerate");

    let mut prover = MuxMulProver::new(vope_r, DerandVOLEReceiver::new(mul_r), false);
    let mut verifier = MuxMulVerifier::new(vope_s, DerandVOLESender::new(mul_s), verifier_bool);
    prover.alloc(num_slots).expect("prover alloc");
    verifier.alloc(num_slots).expect("verifier alloc");
    (prover, verifier, delta)
}

/// A VOLE pool size provisioned far above any API test's actual demand.
pub const IDEAL_VOLE_POOL: usize = 1 << 22;

/// Build a pregenerated ideal RVOLE pair over `Gf2`/`Gf2_64` of pool
/// size `count`. The pair's seed is drawn from `rng`; both halves share
/// `delta` and are pre-filled so the wrapping `DerandVOLE*` pools
/// resolve without an online setup.
///
/// Ideal-functionality scaffolding shared by the API tests and benches.
/// The caller wraps the returned `(sender, receiver)` as it needs —
/// e.g. `DerandVOLEReceiver::new(receiver)` on the prover side, the raw
/// `sender` (or `DerandVOLESender::new(sender)`) on the verifier side.
pub fn ideal_rvole_pair(
    rng: &mut impl Rng,
    delta: Gf2_64,
    count: usize,
) -> (IdealRVOLESender<Gf2_64>, IdealRVOLEReceiver<Gf2, Gf2_64>) {
    let seed: u64 = rng.random();
    let (mut sender, mut receiver) = ideal_rvole::<Gf2, Gf2_64>(seed, delta);
    sender.pregenerate(count);
    receiver
        .pregenerate(count, delta)
        .expect("ideal rvole pregenerate");
    (sender, receiver)
}

/// Low-`n` bits of `val`, least-significant-bit first — the protocols'
/// canonical bundle encoding of a small integer.
pub fn bits(val: u64, n: usize) -> Vec<Gf2> {
    Vec::<Gf2>::from_lsb0_iter(val.iter_lsb0().take(n))
}

/// `base^exp` in `GF(2^n)` modulo `poly`, via square-and-multiply over
/// [`gf2n_mul_mod`].
pub fn pow_mod(base: u64, mut exp: u64, poly: u64, n: usize) -> u64 {
    let mut result = 1u64;
    let mut b = base;
    while exp > 0 {
        if exp & 1 == 1 {
            result = gf2n_mul_mod(result, b, poly, n);
        }
        b = gf2n_mul_mod(b, b, poly, n);
        exp >>= 1;
    }
    result
}

// ---------------------------------------------------------------------------
// RAM witness generation
// ---------------------------------------------------------------------------

/// A randomly generated RAM session for the API tests and benches, in
/// the `Char2Strategy<Gf2_64>` encoding (`Gf2` bundles).
pub struct RamWitness {
    /// Public starting state — one value per live address, in
    /// ascending-address order, as `l_val`-bit bundles. Matches the
    /// order `Prover::setup` / `Verifier::setup` consume.
    pub initial_memory: Vec<Vec<Gf2>>,
    /// The prover's witness: the access trace as `[op, addr, value]`
    /// bundles, ready for `commit_accesses` and both sides' `access`.
    /// `op = 1` is a store, `op = 0` a load.
    pub accesses: Vec<[Vec<Gf2>; 3]>,
    /// Cleartext memory after applying the trace, in the same
    /// ascending-address order as [`initial_memory`](Self::initial_memory).
    pub final_memory: Vec<Vec<Gf2>>,
}

/// Generate a random RAM session over an arbitrary live-address set:
/// one initial cell per address in `live_addrs` and `total_accesses`
/// random read/write accesses, each addressing a *live* cell with a
/// value in `0..2^value_bits`. `live_addrs` need not be zero-based or
/// contiguous — addresses are encoded against the bound
/// `live_addrs.end()` (matching the prover), and holes are never
/// accessed. A cleartext shadow keeps the trace self-consistent and
/// reports the resulting state.
///
/// The verifier needs only [`RamWitness::initial_memory`]; the prover
/// additionally drives the [`RamWitness::accesses`] witness. (In this
/// committed-access harness both sides consume the committed trace.)
pub fn generate_ram_witness(
    live_addrs: &RangeSet<usize>,
    value_bits: usize,
    total_accesses: usize,
    rng: &mut impl Rng,
) -> RamWitness {
    let address_bound = live_addrs.end().expect("live_addrs must be non-empty");
    let l_addr = Char2Strategy::<Gf2_64>::wire_length_for(address_bound);
    let l_val = Char2Strategy::<Gf2_64>::wire_length_for_log2(value_bits);

    // Live addresses in ascending order, each seeded with a random
    // value. The shadow is keyed by address so holes carry no state.
    let live: Vec<usize> = live_addrs.iter_values().collect();
    let mut shadow: BTreeMap<usize, u64> = live
        .iter()
        .map(|&a| (a, sample_value(value_bits, rng)))
        .collect();
    let initial_memory: Vec<Vec<Gf2>> = live.iter().map(|a| bits(shadow[a], l_val)).collect();

    let mut accesses = Vec::with_capacity(total_accesses);
    for _ in 0..total_accesses {
        let addr = live[rng.random_range(0..live.len())];
        let is_write: bool = rng.random();
        // For a load the value is ignored by the mux but still
        // committed, so a random in-range value is fine.
        let value = sample_value(value_bits, rng);
        if is_write {
            shadow.insert(addr, value);
        }
        let op = Gf2(is_write);
        accesses.push([vec![op], bits(addr as u64, l_addr), bits(value, l_val)]);
    }

    let final_memory: Vec<Vec<Gf2>> = live.iter().map(|a| bits(shadow[a], l_val)).collect();
    RamWitness {
        initial_memory,
        accesses,
        final_memory,
    }
}

/// Sample a uniform value from the `value_bits`-wide domain
/// `0..2^value_bits` (`value_bits ≤ 64`).
fn sample_value(value_bits: usize, rng: &mut impl Rng) -> u64 {
    assert!(
        value_bits <= 64,
        "sample_value: value_bits={value_bits} > 64"
    );
    if value_bits == 64 {
        rng.random()
    } else {
        rng.random_range(0..1u64 << value_bits)
    }
}

// ---------------------------------------------------------------------------
// RO-KVS witness generation
// ---------------------------------------------------------------------------

/// A randomly generated RO-KVS session for the API tests and benches, in
/// the `Char2Strategy<Gf2_64>` encoding (`Gf2` bundles).
pub struct RoKvsWitness {
    /// Public key→value content — one value per implicit key
    /// `0..key_space`, as `l_val`-bit bundles. Both prover and verifier
    /// set up from this.
    pub content: Vec<Vec<Gf2>>,
    /// The lookup trace: `num_lookups` random keys, each a single
    /// `[key]` bundle ready for `commit_accesses::<_, _, 1>`.
    pub lookups: Vec<[Vec<Gf2>; 1]>,
}

/// Generate a random RO-KVS session: `key_space` key→value entries
/// (values in `0..2^value_bits`) and `num_lookups` lookups of random
/// keys in `0..key_space`. RO-KVS is read-only — every key is populated
/// and the content is fixed, so there is no shadow to track.
pub fn generate_ro_kvs_witness(
    key_space: usize,
    value_bits: usize,
    num_lookups: usize,
    rng: &mut impl Rng,
) -> RoKvsWitness {
    let l_key = Char2Strategy::<Gf2_64>::wire_length_for(key_space);
    let l_val = Char2Strategy::<Gf2_64>::wire_length_for_log2(value_bits);

    let content: Vec<Vec<Gf2>> = (0..key_space)
        .map(|_| bits(sample_value(value_bits, rng), l_val))
        .collect();
    let lookups: Vec<[Vec<Gf2>; 1]> = (0..num_lookups)
        .map(|_| [bits(rng.random_range(0..key_space) as u64, l_key)])
        .collect();

    RoKvsWitness { content, lookups }
}

// ---------------------------------------------------------------------------
// Set-membership witness generation
// ---------------------------------------------------------------------------

/// A randomly generated set-membership session for the API tests, in
/// the `Char2Strategy<Gf2_64>` encoding (`Gf2` bundles).
pub struct SetWitness {
    /// The set members — `set_size` distinct elements drawn from
    /// `0..element_space`, ascending, as `l_elem`-bit bundles. Both
    /// prover and verifier set up from this.
    pub members: Vec<Vec<Gf2>>,
    /// The lookup trace: `num_lookups` elements, each a single
    /// `[element]` bundle ready for `commit_accesses::<_, _, 1>`. Every
    /// lookup is a member (repeats allowed), so the prover's shadow
    /// lookup always resolves in-set.
    pub lookups: Vec<[Vec<Gf2>; 1]>,
}

/// Generate a random set-membership session: `set_size` distinct
/// members drawn from `0..element_space` and `num_lookups` lookups, each
/// a randomly chosen member (with repeats). `set_size` must not exceed
/// `element_space`.
pub fn generate_set_witness(
    element_space: usize,
    set_size: usize,
    num_lookups: usize,
    rng: &mut impl Rng,
) -> SetWitness {
    assert!(
        set_size <= element_space,
        "set_size {set_size} exceeds element_space {element_space}",
    );
    let l_elem = Char2Strategy::<Gf2_64>::wire_length_for(element_space);

    // Distinct member values, sampled by rejection; `BTreeSet` keeps
    // them ascending.
    let mut chosen: BTreeSet<usize> = BTreeSet::new();
    while chosen.len() < set_size {
        chosen.insert(rng.random_range(0..element_space));
    }
    let member_vals: Vec<usize> = chosen.into_iter().collect();
    let members: Vec<Vec<Gf2>> = member_vals
        .iter()
        .map(|&v| bits(v as u64, l_elem))
        .collect();

    // Lookups: random members (repeats allowed), guaranteed in-set.
    let lookups: Vec<[Vec<Gf2>; 1]> = (0..num_lookups)
        .map(|_| {
            let v = member_vals[rng.random_range(0..member_vals.len())];
            [bits(v as u64, l_elem)]
        })
        .collect();

    SetWitness { members, lookups }
}
