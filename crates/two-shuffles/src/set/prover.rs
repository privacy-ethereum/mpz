//! Prover side of the set membership protocol.

use mpz_common::future::Output;
use mpz_fields::Field;
use mpz_perm_proof_core::{Prover as PermProver, backend::ProverBackend as PermProverBackend};
use mpz_poly_proof_core::ExtensionField;
use mpz_vole_core::{
    DerandVOLEReceiver, DerandVOLEReceiverError, RVOLEReceiver, VOLEReceiver, VoleAdjustment,
};
use serde::Serialize;

use std::collections::BTreeMap;

use super::{Record, TeardownMsg, TeardownPrepare};
use crate::{
    strategy::{
        VersionStrategy,
        version::{ProverVersionStep, VersionStep},
    },
    wire::{Bundle, PackedProverWire, ProverWire as Wire},
};

/// Prover for the set membership protocol.
pub struct Prover<RV, F, B, Strat>
where
    Strat: VersionStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLEReceiver<Strat::S, F>,
    F: Field,
    B: PermProverBackend<F, F>,
{
    /// Wire length for the version.
    l_ver: usize,
    /// Number of distinct elements in the set.
    set_size: usize,
    /// Total number of lookups expected during this session.
    num_lookups: usize,
    /// Running lookup counter, bounded by `num_lookups`.
    lookups_performed: usize,
    /// Lifecycle state.
    state: State,

    /// Per-element version-chain step rule.
    version_step: Strat::VersionStep,

    /// Derandomized VOLE receiver.
    vole: DerandVOLEReceiver<RV, Strat::S, F>,

    /// Permutation protocol prover.
    perm: PermProver<F, F, B>,

    /// Element → slot index. Built at setup, read at lookup.
    index_of: BTreeMap<Bundle<Strat::S>, u32>,

    /// Setup-time key wires, indexed by slot index. Read at teardown.
    setup_wires: Vec<PackedProverWire<F>>,

    /// Cleartext shadow indexed by slot index.
    shadow: Vec<ShadowEntry<Strat::S>>,

    /// Reads log.
    reads: Vec<Record<PackedProverWire<F>>>,

    /// Writes log.
    writes: Vec<Record<PackedProverWire<F>>>,

    /// Outbound queue of `VoleAdjustment` messages.
    pending_adjustments: Vec<VoleAdjustment<F>>,

    /// Fiat-Shamir transcript private to this protocol. Absorbs wire
    /// commitments emitted directly here; embedded sub-protocols own
    /// their own internal transcripts and fold independently.
    transcript: blake3::Hasher,
}

impl<RV, F, B, Strat> Prover<RV, F, B, Strat>
where
    Strat: VersionStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLEReceiver<Strat::S, F>,
    F: Field,
    B: PermProverBackend<F, F>,
{
    /// Construct an empty set prover.
    ///
    /// # Arguments
    ///
    /// * `set_size` — number of distinct members the set will hold.
    /// * `version_step` — version-chain step strategy.
    /// * `vole` — derandomized VOLE receiver.
    /// * `perm` — permutation protocol prover.
    pub fn new(
        set_size: usize,
        version_step: Strat::VersionStep,
        vole: DerandVOLEReceiver<RV, Strat::S, F>,
        perm: PermProver<F, F, B>,
    ) -> Result<Self, Error> {
        if set_size > u32::MAX as usize {
            return Err(Error::SetSizeTooLarge);
        }
        let l_ver = version_step.len();
        let k = <F as ExtensionField<Strat::S>>::MONOMIAL_BASIS.len();
        if l_ver == 0 || l_ver > k {
            return Err(Error::LengthMismatch);
        }
        Ok(Self {
            l_ver,
            set_size,
            num_lookups: 0,
            lookups_performed: 0,
            state: State::Initialized,
            version_step,
            vole,
            perm,
            index_of: BTreeMap::new(),
            setup_wires: Vec::with_capacity(set_size),
            shadow: Vec::with_capacity(set_size),
            reads: Vec::new(),
            writes: Vec::new(),
            pending_adjustments: Vec::new(),
            transcript: blake3::Hasher::new(),
        })
    }

    /// Allocates resources. Must be called exactly once.
    ///
    /// # Arguments
    ///
    /// * `num_lookups` — number of lookups expected during the session.
    pub fn alloc(&mut self, num_lookups: usize) -> Result<(), Error> {
        if self.state != State::Initialized {
            return Err(Error::WrongState(self.state));
        }
        if (num_lookups as u64) > self.version_step.max_advances() {
            return Err(Error::TooManyLookupsForVersionChain);
        }
        self.num_lookups = num_lookups;
        // VOLE correlations:
        //   per lookup:        l_ver
        //   per teardown read: l_ver
        let vole_count = (num_lookups + self.set_size) * self.l_ver;
        self.vole.alloc(vole_count).map_err(Error::Vole)?;

        // Permutation vectors:
        //   writes = setup + lookups
        //   reads  = teardown (set_size) + lookups
        self.perm
            .alloc(self.set_size + num_lookups)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        // Pre-size the reads/writes logs to their final capacities
        // so the hot path is push-only.
        self.reads.reserve_exact(self.set_size + num_lookups);
        self.writes.reserve_exact(self.set_size + num_lookups);

        self.state = State::Allocated;
        Ok(())
    }

    /// Initialize the set with public cleartext elements.
    pub fn setup(&mut self, members: Vec<Bundle<Strat::S>>) -> Result<(), Error>
    where
        Strat::S: Ord + Clone,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        let wired = members.into_iter().map(Wire::constant).collect();
        self.setup_with_wires(wired)
    }

    /// Initialize the set with pre-authenticated element wires.
    pub fn setup_with_wires(&mut self, members: Vec<Wire<Strat::S, F>>) -> Result<(), Error>
    where
        Strat::S: Ord + Clone,
    {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if members.len() != self.set_size {
            return Err(Error::SetSizeMismatch {
                expected: self.set_size,
                got: members.len(),
            });
        }

        let anchor_input = self.version_step.anchor();

        for (idx, member) in members.into_iter().enumerate() {
            let key_cleartext = member.value().clone();
            let key = (&member).into();

            self.index_of.insert(key_cleartext, idx as u32);
            self.setup_wires.push(key);
            self.shadow.push(ShadowEntry {
                version: anchor_input.value().clone(),
            });

            self.writes.push(Record {
                key,
                version: (&anchor_input).into(),
            });
        }

        self.state = State::Setup;
        Ok(())
    }

    /// Prove that `element` is a member of the set.
    pub fn lookup(&mut self, element: Wire<Strat::S, F>) -> Result<(), Error>
    where
        Strat::S: Ord + Clone,
        F: Copy + Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        if self.lookups_performed >= self.num_lookups {
            return Err(Error::LookupCountExceeded);
        }
        self.lookups_performed += 1;

        let idx = *self.index_of.get(element.value()).ok_or(Error::NotInSet)? as usize;
        let version_cleartext = self.shadow[idx].version.clone();

        let mut ver_fut = self
            .vole
            .queue_recv_vole(&version_cleartext)
            .map_err(Error::Vole)?;
        let adjustment = self.vole.adjust().map_err(Error::Vole)?;
        self.transcript
            .update(&bcs::to_bytes(&adjustment).expect("serialize"));
        self.pending_adjustments.push(adjustment);

        let ver_macs: Vec<F> = ver_fut
            .try_recv()
            .map_err(|_| Error::VoleFutureUnresolved)?
            .ok_or(Error::VoleFutureUnresolved)?
            .macs;

        let version_input = Wire::new(version_cleartext, ver_macs.into());

        let next_version_input = self.version_step.next(&version_input);

        self.shadow[idx].version = next_version_input.value().clone();

        let key = (&element).into();

        self.reads.push(Record {
            key,
            version: (&version_input).into(),
        });
        self.writes.push(Record {
            key,
            version: (&next_version_input).into(),
        });

        Ok(())
    }

    /// Pre-`teardown` setup.
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`setup_with_wires`](Self::setup_with_wires) or to
    /// [`lookup`](Self::lookup) before this call — otherwise the
    /// protocol's soundness guarantee against a malicious prover no
    /// longer holds.
    pub fn teardown_prepare(
        &mut self,
        transcript: &mut blake3::Hasher,
    ) -> Result<TeardownPrepare<F, B::Preparation>, Error>
    where
        Strat::S: Ord + Clone,
        F: Copy + Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }

        let teardown_data: Vec<(PackedProverWire<F>, Bundle<Strat::S>)> = self
            .setup_wires
            .iter()
            .zip(self.shadow.iter())
            .map(|(key, entry)| (*key, entry.version.clone()))
            .collect();

        // Queue for derandomization.
        let mut version_futs = Vec::with_capacity(teardown_data.len());
        for (_, ver_cleartext) in &teardown_data {
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

        for ((key_wire, ver_cleartext), mut fut) in teardown_data.into_iter().zip(version_futs) {
            // Compute the next-version input wire.
            let ver_macs: Vec<F> = fut
                .try_recv()
                .map_err(|_| Error::VoleFutureUnresolved)?
                .ok_or(Error::VoleFutureUnresolved)?
                .macs;
            if ver_macs.len() != self.l_ver {
                return Err(Error::LengthMismatch);
            }
            let version_input = Wire::new(ver_cleartext, ver_macs.into());

            self.reads.push(Record {
                key: key_wire,
                version: (&version_input).into(),
            });
        }

        // Convert records to (Vec<Vec<F>>, Vec<Vec<F>>) shape
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
    /// protocol's soundness guarantee against a malicious prover no
    /// longer holds.
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

impl<F: Copy> Record<PackedProverWire<F>> {
    /// Decompose into `(values, macs)` slot vectors in `key, version`
    /// order.
    fn to_parts(&self) -> (Vec<F>, Vec<F>) {
        (
            vec![self.key.value, self.version.value],
            vec![self.key.mac, self.version.mac],
        )
    }
}

/// Per-element shadow entry — cleartext mirror of current version.
struct ShadowEntry<S> {
    /// Cleartext version, advanced on each successful lookup.
    version: Bundle<S>,
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

/// Set prover error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The looked-up element is not a registered set member.
    #[error("element not in set")]
    NotInSet,

    /// More lookups than declared at `alloc` were attempted.
    #[error("lookup count exceeded num_lookups")]
    LookupCountExceeded,

    /// `num_lookups` exceeds the version chain's cycle length.
    #[error("num_lookups exceeds version-chain cycle length")]
    TooManyLookupsForVersionChain,

    /// `set_size` does not fit in `u32`.
    #[error("set_size exceeds u32::MAX")]
    SetSizeTooLarge,

    /// A wire's length does not match the configured one.
    #[error("bundle length mismatch")]
    LengthMismatch,

    /// `members.len()` did not match the `set_size` declared at
    /// construction.
    #[error("set size mismatch: expected {expected}, got {got}")]
    SetSizeMismatch {
        /// `set_size` from the constructor.
        expected: usize,
        /// `members.len()` actually passed to setup.
        got: usize,
    },

    /// A method was called while the prover was in the wrong
    /// lifecycle state.
    #[error("prover method called from wrong state: {0:?}")]
    WrongState(State),

    /// Underlying VOLE receiver error.
    #[error("VOLE error: {0}")]
    Vole(#[source] DerandVOLEReceiverError),

    /// A queued VOLE future failed to resolve.
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
        strategy::{Char2Strategy, version::MultiplicativeStep},
        test_utils::{bits, prover_wire},
    };
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use mpz_perm_proof_core::test_utils::build_ideal_perm_proof_pair;
    use mpz_vole_core::ideal::rvole::ideal_rvole;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// The cleartext set model: `lookup` admits members and rejects
    /// non-members (`NotInSet`), and each admitted lookup advances
    /// exactly that element's version chain by one step while leaving
    /// other elements untouched.
    #[test]
    fn lookup_membership_and_version_chain() {
        const N_VER: usize = 8;
        const FAN_IN: usize = 8;

        // Members live at slots 0..4, keyed by value.
        let members = [0b0000_0001u64, 0b0000_0010, 0b0000_0011, 0b0000_0100];
        // Lookup script (by value): slot 1 twice, slots 2 and 3 once,
        // slot 0 never.
        let lookups = [members[1], members[2], members[1], members[3]];
        let non_member = 0b1111_1111u64;

        let set_size = members.len();
        // One extra slot for the trailing non-member probe.
        let num_lookups = lookups.len() + 1;

        let mut rng = StdRng::seed_from_u64(0x5e7);
        let delta: Gf2_64 = rng.random();

        // Single derand VOLE pool — mirrors `alloc`'s sizing.
        let vole_count = (num_lookups + set_size) * N_VER;
        let (_, mut r) = ideal_rvole::<Gf2, Gf2_64>(rng.random(), delta);
        r.pregenerate(vole_count, delta).expect("pregen");
        let vole = DerandVOLEReceiver::new(r);

        // Perm-proof prover; verifier half dropped (prover-only test).
        let (perm, _) =
            build_ideal_perm_proof_pair(&mut rng, delta, set_size + num_lookups, FAN_IN);

        let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
            set_size,
            MultiplicativeStep::new(N_VER).expect("step"),
            vole,
            perm,
        )
        .expect("prover");
        prover.alloc(num_lookups).expect("alloc");
        prover
            .setup(
                members
                    .iter()
                    .map(|&v| Bundle::from(bits(v, N_VER)))
                    .collect(),
            )
            .expect("setup");

        // Members are admitted.
        for &v in &lookups {
            prover
                .lookup(prover_wire(bits(v, N_VER)))
                .expect("member lookup");
        }
        // A non-member is rejected (consumes a slot, touches no shadow).
        match prover.lookup(prover_wire(bits(non_member, N_VER))) {
            Err(Error::NotInSet) => {}
            other => panic!("non-member must be rejected with NotInSet, got {other:?}"),
        }

        // Expected version chain: `versions[k]` is the anchor advanced
        // `k` steps, computed with a parallel step instance.
        let mut step = MultiplicativeStep::new(N_VER).expect("step");
        let anchor: crate::wire::ProverWire<Gf2, Gf2_64> = step.anchor();
        let mut versions = vec![anchor.value().clone()];
        let mut cur = anchor;
        for _ in 0..lookups.len() {
            let next = step.next(&cur);
            versions.push(next.value().clone());
            cur = next;
        }

        // Each element's version advanced once per lookup of it.
        let mut counts = vec![0usize; set_size];
        for &v in &lookups {
            let slot = members.iter().position(|&m| m == v).expect("member");
            counts[slot] += 1;
        }
        for slot in 0..set_size {
            assert_eq!(
                prover.shadow[slot].version.as_slice(),
                versions[counts[slot]].as_slice(),
                "slot {slot} version chain mismatch after {} lookup(s)",
                counts[slot],
            );
        }
    }
}
