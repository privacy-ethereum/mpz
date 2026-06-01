//! Verifier side of the RO-KVS protocol.

use mpz_fields::Field;
use mpz_perm_proof_core::{
    Verifier as PermVerifier, backend::VerifierBackend as PermVerifierBackend,
};
use mpz_poly_proof_core::ExtensionField;
use mpz_vole_core::{DerandVOLESender, DerandVOLESenderError, RVOLESender, VoleAdjustment};
use serde::Serialize;

use super::{Record, TeardownMsg, TeardownPrepare};
use crate::{
    strategy::{
        VersionStrategy,
        version::{VerifierVersionStep, VersionStep},
    },
    wire::{PackedVerifierWire as PackedWire, VerifierWire as Wire},
};

/// Verifier for the RO-KVS protocol.
pub struct Verifier<RV, F, B, Strat>
where
    Strat: VersionStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLESender<F>,
    F: Field,
    B: PermVerifierBackend<F, F>,
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

    /// Global correlation key.
    delta: F,

    /// Version-chain step strategy.
    version_step: Strat::VersionStep,

    /// Derandomized VOLE sender.
    vole: DerandVOLESender<RV, F>,

    /// Permutation protocol verifier.
    perm: PermVerifier<F, F, B>,

    /// Per-lookup key wires.
    pending_lookups: Vec<PackedWire<F>>,

    /// Setup-time (key, value) wires, indexed by key (=
    /// position in `0..key_space`).
    setup_wires: Vec<(PackedWire<F>, PackedWire<F>)>,

    /// Fiat-Shamir transcript private to this protocol. Absorbs wire
    /// commitments emitted directly here; embedded sub-protocols own
    /// their own internal transcripts and fold independently.
    transcript: blake3::Hasher,

    /// Lifecycle state.
    state: State,
}

impl<RV, F, B, Strat> Verifier<RV, F, B, Strat>
where
    Strat: VersionStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLESender<F>,
    F: Field,
    B: PermVerifierBackend<F, F>,
{
    /// Construct an empty RO-KVS verifier.
    ///
    /// # Arguments
    ///
    /// * `key_space` — cardinality of the key space.
    /// * `value_bits` — bit-width of the value domain (`2^value_bits` distinct
    ///   values).
    /// * `version_step` — version-chain step strategy.
    /// * `rvole` — random VOLE sender.
    /// * `perm` — permutation protocol verifier.
    pub fn new(
        key_space: usize,
        value_bits: usize,
        version_step: Strat::VersionStep,
        rvole: RV,
        perm: PermVerifier<F, F, B>,
    ) -> Result<Self, Error> {
        let l_key = Strat::wire_length_for(key_space);
        let l_val = Strat::wire_length_for_log2(value_bits);
        let l_ver = version_step.len();
        let k = <F as ExtensionField<Strat::S>>::MONOMIAL_BASIS.len();
        if l_ver == 0 || l_ver > k {
            return Err(Error::LengthMismatch);
        }
        let delta = rvole.delta();
        Ok(Self {
            key_space,
            num_lookups: 0,
            lookups_performed: 0,
            l_key,
            l_val,
            l_ver,
            delta,
            version_step,
            vole: DerandVOLESender::new(rvole),
            perm,
            pending_lookups: Vec::new(),
            setup_wires: Vec::with_capacity(key_space),
            transcript: blake3::Hasher::new(),
            state: State::Initialized,
        })
    }

    /// Allocate VOLE correlations and perm-proof state.
    pub fn alloc(&mut self, n_setup: usize, num_lookups: usize) -> Result<(), Error> {
        if self.state != State::Initialized {
            return Err(Error::WrongState(self.state));
        }
        // Per-key version-chain cycle must accommodate the worst case:
        // a single key absorbing every lookup.
        if (num_lookups as u64) > self.version_step.max_advances() {
            return Err(Error::TooManyLookupsForVersionChain);
        }
        self.num_lookups = num_lookups;

        // VOLE correlations:
        //   per lookup:        l_val + l_ver
        //   per teardown read: l_ver (the per-key final version)
        let vole_count = num_lookups * (self.l_val + self.l_ver) + n_setup * self.l_ver;
        self.vole.alloc(vole_count).map_err(Error::DerandVole)?;

        // Permutation vectors:
        //   writes = setup + lookups
        //   reads  = teardown (same size as setup) + lookups
        self.perm
            .alloc(n_setup + num_lookups)
            .map_err(|e| Error::PermProof(Box::new(e)))?;
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
        let wired: Vec<_> = values
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                let key_bundle = Strat::index_to_bundle(i as u32, self.l_key);
                let key_wire = Wire::constant(&key_bundle, self.delta);
                let val_wire = Wire::constant(&v, self.delta);
                (key_wire, val_wire)
            })
            .collect();
        self.setup_with_wires(wired)
    }

    /// Populate the RO-KVS with pre-authenticated wires.
    ///
    /// `content.len()` must equal `key_space`, and the i-th `key_wire`'s
    /// cleartext must encode index `i` — i.e., keys are still the implicit
    /// sequence `0..key_space`.
    pub fn setup_with_wires(&mut self, content: Vec<(Wire<F>, Wire<F>)>) -> Result<(), Error> {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if content.len() != self.key_space {
            return Err(Error::LengthMismatch);
        }

        for (key_wire, value_wire) in content {
            if key_wire.len() != self.l_key || value_wire.len() != self.l_val {
                return Err(Error::LengthMismatch);
            }

            let key_packed = key_wire.pack::<Strat::S>();
            let value_packed = value_wire.pack::<Strat::S>();
            self.setup_wires.push((key_packed, value_packed));
        }

        self.state = State::Setup;
        Ok(())
    }

    /// Record a lookup of the `key` wire.
    pub fn lookup(&mut self, key: Wire<F>) -> Result<(), Error> {
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
        self.pending_lookups.push(key.pack::<Strat::S>());
        Ok(())
    }

    /// Pre-`teardown` processing. Consumes the prover's
    /// [`TeardownPrepare`] message.
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`setup_with_wires`](Self::setup_with_wires) or to
    /// [`lookup`](Self::lookup) before this call — otherwise the
    /// protocol's soundness guarantee no longer holds.
    pub fn teardown_prepare(
        &mut self,
        transcript: &mut blake3::Hasher,
        msg: TeardownPrepare<F, B::Preparation>,
    ) -> Result<(), Error>
    where
        F: Copy + Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        let num_lookups = self.pending_lookups.len();
        let expected_adjs = num_lookups + 1; // one per lookup + one teardown
        if msg.adjustments.len() != expected_adjs {
            return Err(Error::LengthMismatch);
        }

        // Reads and writes only exist within this method; materialize
        // locally, drain into the perm-proof, discard.
        let mut reads: Vec<Record<PackedWire<F>>> =
            Vec::with_capacity(num_lookups + self.key_space);
        let mut writes: Vec<Record<PackedWire<F>>> =
            Vec::with_capacity(num_lookups + self.key_space);

        // Seed `writes` with the setup-time records (one per key,
        // version = anchor).
        let anchor_packed = self.version_step.anchor(self.delta).pack::<Strat::S>();
        for &(key, value) in &self.setup_wires {
            writes.push(Record {
                key,
                value,
                version: anchor_packed,
            });
        }

        // Process per-lookup adjustments.
        for i in 0..num_lookups {
            let adj = &msg.adjustments[i];
            self.transcript
                .update(&bcs::to_bytes(adj).expect("serialize"));
            let key = self.pending_lookups[i];
            self.process_lookup_adjustment(&mut reads, &mut writes, adj, key)?;
        }

        // Process the teardown adjustment.
        let teardown_adj = &msg.adjustments[num_lookups];
        self.transcript
            .update(&bcs::to_bytes(teardown_adj).expect("serialize"));
        if teardown_adj.diffs.len() != self.key_space * self.l_ver {
            return Err(Error::LengthMismatch);
        }
        // Per-key derand pulls — one per `queue_recv_vole` chunk the
        // prover queued in its own teardown loop — so the RVOLE
        // sample pairing stays aligned with the prover.
        for i in 0..self.key_space {
            let (key, value) = self.setup_wires[i];
            let sub = VoleAdjustment {
                diffs: teardown_adj.diffs[i * self.l_ver..(i + 1) * self.l_ver].to_vec(),
            };
            let version_keys = self.vole.adjust(&sub).map_err(Error::DerandVole)?;
            let version_packed = PackedWire::pack::<Strat::S>(&version_keys);

            reads.push(Record {
                key,
                value,
                version: version_packed,
            });
        }

        // Fold the protocol-internal transcript.
        transcript.update(self.transcript.finalize().as_bytes());

        // Convert records to the (Vec<Vec<F>>) shape perm-proof expects.
        let read_keys: Vec<Vec<F>> = reads.iter().map(|r| r.to_keys()).collect();
        let write_keys: Vec<Vec<F>> = writes.iter().map(|r| r.to_keys()).collect();

        self.perm
            .prepare(transcript, &read_keys, &write_keys, msg.preparation)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        self.state = State::TeardownPrepared;
        Ok(())
    }

    /// Tear down the instance, consuming the tear down message from the prover.
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`setup_with_wires`](Self::setup_with_wires) or to
    /// [`lookup`](Self::lookup) before this call — otherwise the
    /// protocol's soundness guarantee no longer holds.
    pub fn teardown(
        self,
        msg: TeardownMsg<F, B::BackendProof>,
        transcript: &mut blake3::Hasher,
    ) -> Result<(), Error>
    where
        F: Copy + Serialize,
        B::BackendProof: Serialize,
    {
        if self.state != State::TeardownPrepared {
            return Err(Error::WrongState(self.state));
        }
        self.perm
            .verify(msg.proof, transcript)
            .map_err(|e| Error::PermProof(Box::new(e)))
    }

    /// Consume one lookup adjustment: derive value and version wires,
    /// advance to next version, and append the corresponding read/write
    /// records.
    fn process_lookup_adjustment(
        &mut self,
        reads: &mut Vec<Record<PackedWire<F>>>,
        writes: &mut Vec<Record<PackedWire<F>>>,
        adj: &VoleAdjustment<F>,
        key: PackedWire<F>,
    ) -> Result<(), Error> {
        let n_total = self.l_val + self.l_ver;
        if adj.diffs.len() != n_total {
            return Err(Error::LengthMismatch);
        }

        // Two derand pulls — one per `queue_recv_vole` chunk the
        // prover queued (value, then version) — so the RVOLE sample
        // pairing stays aligned with the prover.
        let val_adj = VoleAdjustment {
            diffs: adj.diffs[..self.l_val].to_vec(),
        };
        let value_keys = self.vole.adjust(&val_adj).map_err(Error::DerandVole)?;
        let ver_adj = VoleAdjustment {
            diffs: adj.diffs[self.l_val..].to_vec(),
        };
        let version_keys = self.vole.adjust(&ver_adj).map_err(Error::DerandVole)?;

        let version_wire: Wire<F> = version_keys.into();
        let next_version_wire = self.version_step.next(&version_wire, self.delta);

        let value_packed = PackedWire::pack::<Strat::S>(&value_keys);

        reads.push(Record {
            key,
            value: value_packed,
            version: version_wire.pack::<Strat::S>(),
        });
        writes.push(Record {
            key,
            value: value_packed,
            version: next_version_wire.pack::<Strat::S>(),
        });

        Ok(())
    }
}

impl<F: Copy> Record<PackedWire<F>> {
    /// Extract the keys in `key, value, version` order.
    fn to_keys(&self) -> Vec<F> {
        vec![self.key.key, self.value.key, self.version.key]
    }
}

/// Lifecycle state for the [`Verifier`].
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

/// RO-KVS verifier error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A method was called while the verifier was in the wrong state.
    #[error("wrong verifier state: {0:?}")]
    WrongState(State),

    /// More lookups than declared at `alloc` were attempted.
    #[error("lookup count exceeded num_lookups")]
    LookupCountExceeded,

    /// `num_lookups` exceeds the version chain's cycle length.
    #[error("num_lookups exceeds version-chain cycle length")]
    TooManyLookupsForVersionChain,

    /// A wire's length does not match the configured one.
    #[error("bundle length mismatch")]
    LengthMismatch,

    /// Derandomized VOLE sender error.
    #[error("derand VOLE error: {0}")]
    DerandVole(#[source] DerandVOLESenderError),

    /// Permutation-proof error.
    #[error("permutation-proof error: {0}")]
    PermProof(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}
