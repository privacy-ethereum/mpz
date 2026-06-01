//! Prover side of the RO-KVS protocol.

use mpz_common::future::Output;
use mpz_fields::Field;
use mpz_perm_proof_core::{Prover as PermProver, backend::ProverBackend as PermProverBackend};
use mpz_poly_proof_core::ExtensionField;
use mpz_vole_core::{
    DerandVOLEReceiver, DerandVOLEReceiverError, RVOLEReceiver, VOLEReceiver, VoleAdjustment,
};
use serde::Serialize;

use super::{Record, TeardownMsg, TeardownPrepare};
use crate::{
    strategy::{
        VersionStrategy,
        version::{ProverVersionStep, VersionStep},
    },
    wire::{Bundle, PackedProverWire as PackedWire, ProverWire as Wire},
};

/// Prover for the RO-KVS protocol.
pub struct Prover<RV, F, B, Strat>
where
    Strat: VersionStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLEReceiver<Strat::S, F>,
    F: Field,
    B: PermProverBackend<F, F>,
{
    /// Cardinality of the key space.
    key_space: usize,

    /// Total number of lookups expected during this session.
    num_lookups: usize,

    /// Running lookup counter, bounded by `num_lookups`.
    lookups_performed: usize,

    /// Wire length for keys.
    l_key: usize,

    /// Wire length for values.
    l_val: usize,

    /// Wire length for versions.
    l_ver: usize,

    /// Version-chain step strategy.
    version_step: Strat::VersionStep,

    /// Derandomized VOLE receiver.
    vole: DerandVOLEReceiver<RV, Strat::S, F>,

    /// Permutation protocol prover.
    perm: PermProver<F, F, B>,

    /// Cleartext shadow indexed by key (= position in `0..key_space`).
    shadow: Vec<ShadowEntry<Strat::S>>,

    /// Setup-time packed wires per key, kept for replay at teardown.
    setup_wires: Vec<(PackedWire<F>, PackedWire<F>)>,

    /// Reads log.
    reads: Vec<Record<PackedWire<F>>>,

    /// Writes log.
    writes: Vec<Record<PackedWire<F>>>,

    /// Outbound queue of `VoleAdjustment` messages.
    pending_adjustments: Vec<VoleAdjustment<F>>,

    /// Fiat-Shamir transcript private to this protocol. Absorbs wire
    /// commitments emitted directly here; embedded sub-protocols own
    /// their own internal transcripts and fold independently.
    transcript: blake3::Hasher,

    /// Lifecycle state.
    state: State,
}

impl<RV, F, B, Strat> Prover<RV, F, B, Strat>
where
    Strat: VersionStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLEReceiver<Strat::S, F>,
    F: Field,
    B: PermProverBackend<F, F>,
{
    /// Construct an empty RO-KVS prover.
    ///
    /// # Arguments
    ///
    /// * `key_space` — cardinality of the key space.
    /// * `value_bits` — bit-width of the value domain (`2^value_bits` distinct
    ///   values).
    /// * `version_step` — version-chain step strategy.
    /// * `vole` — derandomized VOLE receiver.
    /// * `perm` — permutation protocol prover.
    pub fn new(
        key_space: usize,
        value_bits: usize,
        version_step: Strat::VersionStep,
        vole: DerandVOLEReceiver<RV, Strat::S, F>,
        perm: PermProver<F, F, B>,
    ) -> Result<Self, Error> {
        let l_key = Strat::wire_length_for(key_space);
        let l_val = Strat::wire_length_for_log2(value_bits);
        let l_ver = version_step.len();
        let k = <F as ExtensionField<Strat::S>>::MONOMIAL_BASIS.len();
        if l_ver == 0 || l_ver > k {
            return Err(Error::LengthMismatch);
        }
        Ok(Self {
            key_space,
            num_lookups: 0,
            lookups_performed: 0,
            l_key,
            l_val,
            l_ver,
            version_step,
            vole,
            perm,
            shadow: Vec::with_capacity(key_space),
            setup_wires: Vec::with_capacity(key_space),
            reads: Vec::new(),
            writes: Vec::new(),
            pending_adjustments: Vec::new(),
            transcript: blake3::Hasher::new(),
            state: State::Initialized,
        })
    }

    /// Allocates resources. Must be called exactly once.
    ///
    /// # Arguments
    ///
    /// * `n_setup` — number of setup entries.
    /// * `num_lookups` — number of lookups expected during the session.
    pub fn alloc(&mut self, n_setup: usize, num_lookups: usize) -> Result<(), Error> {
        if self.state != State::Initialized {
            return Err(Error::WrongState(self.state));
        }
        // Per-key version-chain cycle must accommodate the worst case:
        // a single key absorbing every lookup.
        if (num_lookups as u64) > self.version_step.max_advances() {
            return Err(Error::TooManyLookupsForVersionChain);
        }
        // VOLE correlations:
        //   per lookup:        l_val + l_ver
        //   per teardown read: l_ver (the per-key final version)
        let vole_count = num_lookups * (self.l_val + self.l_ver) + n_setup * self.l_ver;
        self.vole.alloc(vole_count).map_err(Error::Vole)?;

        // Permutation vectors:
        //   writes = setup + lookups
        //   reads  = teardown (same size as setup) + lookups
        self.perm
            .alloc(n_setup + num_lookups)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        // Pre-size the reads/writes logs to their final capacities so
        // the hot path is push-only.
        self.reads.reserve_exact(n_setup + num_lookups);
        self.writes.reserve_exact(n_setup + num_lookups);

        self.num_lookups = num_lookups;
        self.state = State::Allocated;
        Ok(())
    }

    /// Populate the RO-KVS with cleartext initial content.
    ///
    /// Keys are implicit: position `i` of `values` is key `i`. `values.len()`
    /// must equal the configured `key_space`.
    pub fn setup(&mut self, values: Vec<Vec<Strat::S>>) -> Result<(), Error>
    where
        Strat::S: Clone,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if values.len() != self.key_space {
            return Err(Error::LengthMismatch);
        }
        let wired = values
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                let key_bundle = Strat::index_to_bundle(i as u32, self.l_key);
                (Wire::constant(key_bundle), Wire::constant(v))
            })
            .collect();
        self.setup_with_wires(wired)
    }

    /// Populate the RO-KVS with pre-authenticated wires.
    ///
    /// `content.len()` must equal `key_space`, and the i-th `key_wire`'s
    /// cleartext must encode index `i` — i.e., keys are still the implicit
    /// sequence `0..key_space`.
    pub fn setup_with_wires(
        &mut self,
        content: Vec<(Wire<Strat::S, F>, Wire<Strat::S, F>)>,
    ) -> Result<(), Error>
    where
        Strat::S: Clone,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if content.len() != self.key_space {
            return Err(Error::LengthMismatch);
        }

        let anchor_input = self.version_step.anchor();
        let anchor_wire: PackedWire<F> = (&anchor_input).into();

        for (i, (key_input, value_input)) in content.into_iter().enumerate() {
            if key_input.len() != self.l_key || value_input.len() != self.l_val {
                return Err(Error::LengthMismatch);
            }
            if Strat::bundle_to_index(key_input.value()) as usize != i {
                return Err(Error::LengthMismatch);
            }

            let value_cleartext = value_input.value().clone();

            let key_wire = (&key_input).into();
            let value_wire = (&value_input).into();

            self.shadow.push(ShadowEntry {
                value_cleartext,
                version_cleartext: anchor_input.value().clone(),
            });
            self.setup_wires.push((key_wire, value_wire));

            self.writes.push(Record {
                key: key_wire,
                value: value_wire,
                version: anchor_wire,
            });
        }

        self.state = State::Setup;
        Ok(())
    }

    /// Look up the value at `key` and return its authenticated wire.
    pub fn lookup(&mut self, key: Wire<Strat::S, F>) -> Result<Wire<Strat::S, F>, Error>
    where
        Strat::S: Clone,
        F: Copy + Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        if self.lookups_performed >= self.num_lookups {
            return Err(Error::LookupCountExceeded);
        }
        if key.len() != self.l_key {
            return Err(Error::LengthMismatch);
        }
        self.lookups_performed += 1;

        // 1. Shadow lookup by key index.
        let idx = Strat::bundle_to_index(key.value()) as usize;
        if idx >= self.shadow.len() {
            return Err(Error::KeyNotFound);
        }
        let entry = &self.shadow[idx];
        let value_cleartext = entry.value_cleartext.clone();
        let version_cleartext = entry.version_cleartext.clone();

        // 2. Queue for derandomization.
        let mut val_fut = self
            .vole
            .queue_recv_vole(&value_cleartext)
            .map_err(Error::Vole)?;
        let mut ver_fut = self
            .vole
            .queue_recv_vole(&version_cleartext)
            .map_err(Error::Vole)?;

        // 3. Adjust.
        let adjustment = self.vole.adjust().map_err(Error::Vole)?;
        self.transcript
            .update(&bcs::to_bytes(&adjustment).expect("serialize"));
        self.pending_adjustments.push(adjustment);

        // 4. Extract resolved MACs.
        let val_macs: Vec<F> = val_fut
            .try_recv()
            .map_err(|_| Error::VoleFutureUnresolved)?
            .ok_or(Error::VoleFutureUnresolved)?
            .macs;
        let ver_macs: Vec<F> = ver_fut
            .try_recv()
            .map_err(|_| Error::VoleFutureUnresolved)?
            .ok_or(Error::VoleFutureUnresolved)?
            .macs;

        let value_input = Wire::new(value_cleartext, val_macs.into());
        let version_input = Wire::new(version_cleartext, ver_macs.into());

        // 5. Compute the next-version input wire.
        let next_version_input = self.version_step.next(&version_input);

        // 6. Update the shadow's version cleartext.
        self.shadow[idx].version_cleartext = next_version_input.value().clone();

        // 7. Pack the input wires and append records.
        let key_wire = (&key).into();
        let value_wire = (&value_input).into();
        let version_wire = (&version_input).into();
        let next_version_wire = (&next_version_input).into();

        self.reads.push(Record {
            key: key_wire,
            value: value_wire,
            version: version_wire,
        });
        self.writes.push(Record {
            key: key_wire,
            value: value_wire,
            version: next_version_wire,
        });

        Ok(value_input)
    }

    /// Pre-`teardown` setup.
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`setup_with_wires`](Self::setup_with_wires) or to
    /// [`lookup`](Self::lookup) before this call — otherwise the
    /// protocol's soundness guarantee no longer holds.
    pub fn teardown_prepare(
        &mut self,
        transcript: &mut blake3::Hasher,
    ) -> Result<TeardownPrepare<F, B::Preparation>, Error>
    where
        Strat::S: Clone,
        F: Copy + Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        // Append teardown reads.
        let teardown_data: Vec<(PackedWire<F>, PackedWire<F>, Bundle<Strat::S>)> = self
            .shadow
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let (key_wire, value_wire) = self.setup_wires[i];
                (key_wire, value_wire, entry.version_cleartext.clone())
            })
            .collect();

        let mut version_futs = Vec::with_capacity(teardown_data.len());
        for (_, _, ver_cleartext) in &teardown_data {
            let fut = self
                .vole
                .queue_recv_vole(ver_cleartext)
                .map_err(Error::Vole)?;
            version_futs.push(fut);
        }
        let teardown_adjustment = self.vole.adjust().map_err(Error::Vole)?;
        self.transcript
            .update(&bcs::to_bytes(&teardown_adjustment).expect("serialize"));
        self.pending_adjustments.push(teardown_adjustment);

        for ((key_wire, value_wire, ver_cleartext), mut fut) in
            teardown_data.into_iter().zip(version_futs)
        {
            let ver_macs: Vec<F> = fut
                .try_recv()
                .map_err(|_| Error::VoleFutureUnresolved)?
                .ok_or(Error::VoleFutureUnresolved)?
                .macs;
            let version_input = Wire::new(ver_cleartext, ver_macs.into());

            self.reads.push(Record {
                key: key_wire,
                value: value_wire,
                version: (&version_input).into(),
            });
        }

        // Convert records to the (Vec<Vec<F>>, Vec<Vec<F>>) shape
        // expected by perm-proof's prepare.
        let (read_values, read_macs): (Vec<Vec<F>>, Vec<Vec<F>>) =
            self.reads.iter().map(|r| r.to_parts()).unzip();
        let (write_values, write_macs): (Vec<Vec<F>>, Vec<Vec<F>>) =
            self.writes.iter().map(|r| r.to_parts()).unzip();

        // Fold the protocol-internal transcript.
        transcript.update(self.transcript.finalize().as_bytes());

        let preparation = self
            .perm
            .prepare(
                transcript,
                (&read_values, &read_macs),
                (&write_values, &write_macs),
            )
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        self.state = State::TeardownPrepared;
        Ok(TeardownPrepare {
            adjustments: std::mem::take(&mut self.pending_adjustments),
            preparation,
        })
    }

    /// Tear down the instance, returning the message to be sent to the
    /// verifier.
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`setup_with_wires`](Self::setup_with_wires) or to
    /// [`lookup`](Self::lookup) before this call — otherwise the
    /// protocol's soundness guarantee no longer holds.
    pub fn teardown(
        self,
        transcript: &mut blake3::Hasher,
    ) -> Result<TeardownMsg<F, B::BackendProof>, Error>
    where
        F: Copy + Serialize,
        B::BackendProof: Serialize,
    {
        if self.state != State::TeardownPrepared {
            return Err(Error::WrongState(self.state));
        }
        let proof = self
            .perm
            .prove(transcript)
            .map_err(|e| Error::PermProof(Box::new(e)))?;
        Ok(TeardownMsg { proof })
    }
}

impl<F: Copy> Record<PackedWire<F>> {
    /// Decompose into `(values, macs)` slot vectors in `key, value,
    /// version` order.
    fn to_parts(&self) -> (Vec<F>, Vec<F>) {
        (
            vec![self.key.value, self.value.value, self.version.value],
            vec![self.key.mac, self.value.mac, self.version.mac],
        )
    }
}

/// Lifecycle state for the [`Prover`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initialized state.
    Initialized,
    /// Allocated state.
    Allocated,
    /// Setup state.
    Setup,
    /// Teardown-prepared state.
    TeardownPrepared,
}

/// Per-key shadow entry — cleartext mirror of one setup key's value
/// and current version.
struct ShadowEntry<S> {
    /// Value cleartext.
    value_cleartext: Bundle<S>,
    /// Version cleartext.
    version_cleartext: Bundle<S>,
}

/// RO-KVS prover error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A method was called while the prover was in the wrong state.
    #[error("prover method called from wrong state: {0:?}")]
    WrongState(State),

    /// The looked-up key is not in the prover's shadow.
    #[error("key not found in RO-KVS shadow")]
    KeyNotFound,

    /// More lookups than declared at `alloc` were attempted.
    #[error("lookup count exceeded num_lookups")]
    LookupCountExceeded,

    /// `num_lookups` exceeds the version chain's cycle length.
    /// Worst case is all lookups hitting the same key — versions
    /// would wrap and lose distinctness, breaking soundness.
    #[error("num_lookups exceeds version-chain cycle length")]
    TooManyLookupsForVersionChain,

    /// A wire's length does not match the configured one.
    #[error("bundle length mismatch")]
    LengthMismatch,

    /// Underlying VOLE receiver error.
    #[error("VOLE error: {0}")]
    Vole(#[source] DerandVOLEReceiverError),

    /// Internal invariant: a queued VOLE future failed to resolve.
    #[error("VOLE future failed to resolve after adjust")]
    VoleFutureUnresolved,

    /// Permutation-proof error during teardown.
    #[error("permutation-proof error: {0}")]
    PermProof(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use crate::{
        strategy::{Char2Strategy, FieldStrategy, version::MultiplicativeStep},
        test_utils::{bits, prover_wire},
    };
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use mpz_perm_proof_core::test_utils::build_ideal_perm_proof_pair;
    use mpz_vole_core::ideal::rvole::ideal_rvole;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// The cleartext RO-KVS model: every `lookup(key)` returns that
    /// key's setup value (read-only, repeatable, correctly addressed),
    /// and each lookup advances exactly that key's version chain by one
    /// step while leaving other keys untouched.
    #[test]
    fn lookup_cleartext_rokvs_semantics() {
        const KEY_SPACE: usize = 4;
        const VALUE_BITS: usize = 4;
        const N_VER: usize = 8;
        const FAN_IN: usize = 8;

        // Per-key setup values (key i lives at position i).
        let content = vec![
            bits(0b1100, 4), // key 0
            bits(0b0110, 4), // key 1
            bits(0b0011, 4), // key 2
            bits(0b1010, 4), // key 3
        ];
        // Lookup script: key 1 twice, keys 2 and 3 once, key 0 never.
        let lookups = [1usize, 2, 1, 3];
        let n_setup = KEY_SPACE;
        let num_lookups = lookups.len();

        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let delta: Gf2_64 = rng.random();

        let l_key = <Char2Strategy<Gf2_64> as FieldStrategy<Gf2_64>>::wire_length_for(KEY_SPACE);
        let l_val =
            <Char2Strategy<Gf2_64> as FieldStrategy<Gf2_64>>::wire_length_for_log2(VALUE_BITS);

        // Single derand VOLE pool — mirrors `alloc`'s sizing.
        let vole_count = num_lookups * (l_val + N_VER) + n_setup * N_VER;
        let (_, mut r) = ideal_rvole::<Gf2, Gf2_64>(rng.random(), delta);
        r.pregenerate(vole_count, delta).expect("pregen");
        let vole = DerandVOLEReceiver::new(r);

        // Perm-proof prover; verifier half dropped (prover-only test).
        let (perm, _) = build_ideal_perm_proof_pair(&mut rng, delta, n_setup + num_lookups, FAN_IN);

        let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
            KEY_SPACE,
            VALUE_BITS,
            MultiplicativeStep::new(N_VER).expect("step"),
            vole,
            perm,
        )
        .expect("prover");
        prover.alloc(n_setup, num_lookups).expect("alloc");
        prover.setup(content.clone()).expect("setup");

        // Each lookup must return that key's setup value, every time.
        for &key_idx in &lookups {
            let key = prover_wire(bits(key_idx as u64, l_key));
            let got = prover.lookup(key).expect("lookup");
            assert_eq!(
                got.value().as_slice(),
                content[key_idx].as_slice(),
                "lookup(key {key_idx}) returned the wrong value",
            );
        }

        // Expected version chain: `versions[k]` is the anchor advanced
        // `k` steps, computed with a parallel step instance.
        let mut step = MultiplicativeStep::new(N_VER).expect("step");
        let anchor: crate::wire::ProverWire<Gf2, Gf2_64> = step.anchor();
        let mut versions = vec![anchor.value().clone()];
        let mut cur = anchor;
        for _ in 0..num_lookups {
            let next = step.next(&cur);
            versions.push(next.value().clone());
            cur = next;
        }

        // Each key's version advanced exactly once per lookup of it;
        // its value never changed (read-only).
        let mut counts = [0usize; KEY_SPACE];
        for &k in &lookups {
            counts[k] += 1;
        }
        for i in 0..KEY_SPACE {
            assert_eq!(
                prover.shadow[i].value_cleartext.as_slice(),
                content[i].as_slice(),
                "key {i} value must be unchanged (read-only)",
            );
            assert_eq!(
                prover.shadow[i].version_cleartext.as_slice(),
                versions[counts[i]].as_slice(),
                "key {i} version chain mismatch after {} lookup(s)",
                counts[i],
            );
        }
    }
}
