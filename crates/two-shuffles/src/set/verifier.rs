//! Verifier side of the Set membership protocol.

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
    wire::{Bundle, PackedVerifierWire as PackedWire, VerifierWire as Wire},
};

/// Verifier for the set membership protocol.
pub struct Verifier<RV, F, B, Strat>
where
    Strat: VersionStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLESender<F>,
    F: Field,
    B: PermVerifierBackend<F, F>,
{
    /// Wire length for the version chain.
    l_ver: usize,
    /// Number of distinct elements in the set.
    set_size: usize,
    /// Total number of lookups expected during this session.
    num_lookups: usize,
    /// Running lookup counter, bounded by `num_lookups`.
    lookups_performed: usize,
    /// Lifecycle state.
    state: State,

    /// Global correlation key.
    delta: F,

    /// Per-element version-chain step rule.
    version_step: Strat::VersionStep,

    /// Derandomized VOLE sender.
    vole: DerandVOLESender<RV, F>,

    /// Permutation protocol verifier.
    perm: PermVerifier<F, F, B>,

    /// Setup-time key wires, indexed by slot index. Read at teardown.
    setup_wires: Vec<PackedWire<F>>,

    /// Per-lookup key wires.
    pending_lookups: Vec<PackedWire<F>>,

    /// Fiat-Shamir transcript private to this protocol. Absorbs wire
    /// commitments emitted directly here; embedded sub-protocols own
    /// their own internal transcripts and fold independently.
    transcript: blake3::Hasher,
}

impl<RV, F, B, Strat> Verifier<RV, F, B, Strat>
where
    Strat: VersionStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLESender<F>,
    F: Field,
    B: PermVerifierBackend<F, F>,
{
    /// Construct an empty Set verifier.
    ///
    /// # Arguments
    ///
    /// * `set_size` — number of distinct members the set will hold.
    /// * `version_step` — version-chain step strategy.
    /// * `rvole` — random VOLE sender.
    /// * `perm` — permutation protocol verifier.
    pub fn new(
        set_size: usize,
        version_step: Strat::VersionStep,
        rvole: RV,
        perm: PermVerifier<F, F, B>,
    ) -> Result<Self, Error> {
        if set_size > u32::MAX as usize {
            return Err(Error::SetSizeTooLarge);
        }
        let l_ver = version_step.len();
        let k = <F as ExtensionField<Strat::S>>::MONOMIAL_BASIS.len();
        if l_ver == 0 || l_ver > k {
            return Err(Error::LengthMismatch);
        }
        let delta = rvole.delta();
        Ok(Self {
            l_ver,
            set_size,
            num_lookups: 0,
            lookups_performed: 0,
            state: State::Initialized,
            delta,
            version_step,
            vole: DerandVOLESender::new(rvole),
            perm,
            setup_wires: Vec::with_capacity(set_size),
            pending_lookups: Vec::new(),
            transcript: blake3::Hasher::new(),
        })
    }

    /// Allocate VOLE correlations and perm-proof state for
    /// `num_lookups` lookups; setup-side allocation is sized from
    /// `set_size` stored at construction.
    pub fn alloc(&mut self, num_lookups: usize) -> Result<(), Error> {
        if self.state != State::Initialized {
            return Err(Error::WrongState(self.state));
        }
        if (num_lookups as u64) > self.version_step.max_advances() {
            return Err(Error::TooManyLookupsForVersionChain);
        }
        self.num_lookups = num_lookups;
        let vole_count = (num_lookups + self.set_size) * self.l_ver;
        self.vole.alloc(vole_count).map_err(Error::DerandVole)?;
        self.perm
            .alloc(self.set_size + num_lookups)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        self.state = State::Allocated;
        Ok(())
    }

    /// Initialize the set with public cleartext members.
    pub fn setup(&mut self, members: Vec<Bundle<Strat::S>>) -> Result<(), Error>
    where
        Strat::S: Ord + Clone,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        let wired: Vec<_> = members
            .into_iter()
            .map(|k| Wire::constant(&k, self.delta))
            .collect();
        self.setup_with_wires(wired)
    }

    /// Initialize the set with pre-authenticated K wires. Position
    /// `i` of `content` is the K-wire for slot `i`.
    pub fn setup_with_wires(&mut self, content: Vec<Wire<F>>) -> Result<(), Error> {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if content.len() != self.set_size {
            return Err(Error::SetSizeMismatch {
                expected: self.set_size,
                got: content.len(),
            });
        }

        for key_wire in content {
            self.setup_wires.push(key_wire.pack::<Strat::S>());
        }

        self.state = State::Setup;
        Ok(())
    }

    /// Record a membership claim for `element`.
    pub fn lookup(&mut self, element: Wire<F>) -> Result<(), Error> {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        if self.lookups_performed >= self.num_lookups {
            return Err(Error::LookupCountExceeded);
        }
        self.lookups_performed += 1;
        let key_packed = element.pack::<Strat::S>();
        self.pending_lookups.push(key_packed);
        Ok(())
    }

    /// Pre-`teardown` processing. Consumes the prover's
    /// [`TeardownPrepare`] message.
    ///
    /// `transcript` is the caller's transcript. This method mixes
    /// the same adjustment bytes into it that
    /// [`Prover::teardown_prepare`](super::prover::Prover::teardown_prepare)
    /// mixed into its own, so a session that threads one transcript
    /// through every external step stays in sync across the prover /
    /// verifier divide.
    pub fn teardown_prepare(
        &mut self,
        transcript: &mut blake3::Hasher,
        msg: TeardownPrepare<F, B::Preparation>,
    ) -> Result<(), Error>
    where
        Strat::S: Ord + Clone,
        F: Copy + Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        let num_lookups = self.pending_lookups.len();
        let expected_adjs = num_lookups + 1;
        if msg.adjustments.len() != expected_adjs {
            return Err(Error::LengthMismatch);
        }

        let mut reads: Vec<Record<PackedWire<F>>> = Vec::with_capacity(num_lookups + self.set_size);
        let mut writes: Vec<Record<PackedWire<F>>> =
            Vec::with_capacity(num_lookups + self.set_size);

        // Seed `writes` with the setup-time records (one per slot,
        // version = anchor).
        let anchor = self.version_step.anchor(self.delta).pack::<Strat::S>();
        for &key in &self.setup_wires {
            writes.push(Record {
                key,
                version: anchor,
            });
        }

        for i in 0..num_lookups {
            let adj = &msg.adjustments[i];
            self.transcript
                .update(&bcs::to_bytes(adj).expect("serialize"));
            let key_packed = self.pending_lookups[i];
            self.process_lookup_adjustment(&mut reads, &mut writes, adj, key_packed)?;
        }

        // Process the teardown adjustment.
        let teardown_adj = &msg.adjustments[num_lookups];
        self.transcript
            .update(&bcs::to_bytes(teardown_adj).expect("serialize"));
        if teardown_adj.diffs.len() != self.set_size * self.l_ver {
            return Err(Error::LengthMismatch);
        }
        // Per-element derand pulls — one per `queue_recv_vole` chunk
        // the prover queued in its own teardown loop — so the RVOLE
        // sample pairing stays aligned with the prover.
        for i in 0..self.set_size {
            let key = self.setup_wires[i];
            let sub = VoleAdjustment {
                diffs: teardown_adj.diffs[i * self.l_ver..(i + 1) * self.l_ver].to_vec(),
            };
            let version_keys = self.vole.adjust(&sub).map_err(Error::DerandVole)?;
            reads.push(Record {
                key,
                version: PackedWire::pack::<Strat::S>(&version_keys),
            });
        }

        // Fold the protocol-internal transcript.
        transcript.update(self.transcript.finalize().as_bytes());

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
    /// protocol's soundness guarantee against a malicious prover no
    /// longer holds.
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
            .map_err(|e| Error::PermProof(Box::new(e)))?;
        Ok(())
    }

    /// Consume one lookup adjustment: derive version wires,
    /// advance to next version, and append the corresponding read/write
    /// records.
    fn process_lookup_adjustment(
        &mut self,
        reads: &mut Vec<Record<PackedWire<F>>>,
        writes: &mut Vec<Record<PackedWire<F>>>,
        adj: &VoleAdjustment<F>,
        key_packed: PackedWire<F>,
    ) -> Result<(), Error> {
        if adj.diffs.len() != self.l_ver {
            return Err(Error::LengthMismatch);
        }

        let version_keys = self.vole.adjust(adj).map_err(Error::DerandVole)?;
        let version: Wire<F> = version_keys.into();
        let next_version = self.version_step.next(&version, self.delta);

        let version = PackedWire::pack::<Strat::S>(&version.key);
        let next_version = PackedWire::pack::<Strat::S>(&next_version.key);

        reads.push(Record {
            key: key_packed,
            version,
        });
        writes.push(Record {
            key: key_packed,
            version: next_version,
        });

        Ok(())
    }
}

impl<F: Copy> Record<PackedWire<F>> {
    /// Extract the per-slot keys in `key, version` order.
    fn to_keys(&self) -> Vec<F> {
        vec![self.key.key, self.version.key]
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

/// Set verifier error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A wire's length does not match the configured one.
    #[error("bundle length mismatch")]
    LengthMismatch,

    /// More lookups than declared at `alloc` were attempted.
    #[error("lookup count exceeded num_lookups")]
    LookupCountExceeded,

    /// `num_lookups` exceeds the version chain's cycle length.
    #[error("num_lookups exceeds version-chain cycle length")]
    TooManyLookupsForVersionChain,

    /// `set_size` does not fit in `u32`.
    #[error("set_size exceeds u32::MAX")]
    SetSizeTooLarge,

    /// `members.len()` did not match the `set_size` declared at
    /// construction.
    #[error("set size mismatch: expected {expected}, got {got}")]
    SetSizeMismatch {
        /// `set_size` from the constructor.
        expected: usize,
        /// `members.len()` actually passed to setup.
        got: usize,
    },

    /// A method was called in the wrong lifecycle state.
    #[error("wrong verifier state: {0:?}")]
    WrongState(State),

    /// Derandomized VOLE sender error.
    #[error("derand VOLE error: {0}")]
    DerandVole(#[source] DerandVOLESenderError),

    /// Permutation-proof error.
    #[error("permutation-proof error: {0}")]
    PermProof(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}
