//! Verifier side of the RAM protocol.

use mpz_fields::Field;
use mpz_perm_proof_core::{
    Verifier as PermVerifier, backend::VerifierBackend as PermVerifierBackend,
};
use mpz_poly_proof_core::ExtensionField;
use mpz_vole_core::{DerandVOLESender, DerandVOLESenderError, RVOLESender, VoleAdjustment};
use serde::Serialize;

use super::{
    Flush, Record, TeardownMsg, TeardownPrepare,
    clock::{Clock, VerifierClock},
    config::Config,
    mux_mul::MuxMulVerifier,
    strategy::VerifierStrategy,
};
use crate::{
    set,
    wire::{PackedVerifierWire as PackedWire, VerifierWire as Wire},
};
use rangeset::set::RangeSet;

/// RAM verifier.
pub struct Verifier<RV, F, B, Strat>
where
    Strat: VerifierStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLESender<F>,
    F: Field,
    B: PermVerifierBackend<F, F>,
{
    /// Wire length of the address.
    l_addr: usize,
    /// Wire length of the value.
    l_val: usize,
    /// Addresses instantiated at setup.
    live_addrs: RangeSet<usize>,
    /// Total access budget.
    total_accesses: usize,
    /// Running access counter, bounded by `total_accesses`.
    accesses_performed: usize,
    /// Lifecycle state. Enforces the call-order contract at runtime.
    state: State,

    /// Global correlation key.
    delta: F,

    /// Clock strategy.
    clock: Strat::Clock,

    /// Derandomized VOLE sender.
    vole: DerandVOLESender<RV, F>,

    /// Permutation protocol verifier.
    perm_verifier: PermVerifier<F, F, B>,

    /// Set-membership verifier.
    set_verifier: set::Verifier<RV, F, B, Strat>,

    /// Mux-multiplication verifier.
    mux_mul_verifier: MuxMulVerifier<RV, RV, Strat::S, F>,

    /// Pending accesses.
    pending_accesses: Vec<PendingAccess<F>>,

    /// Reads log.
    reads: Vec<Record<PackedWire<F>>>,

    /// Writes log.
    writes: Vec<Record<PackedWire<F>>>,

    /// Fiat-Shamir transcript private to this protocol. Absorbs wire
    /// commitments emitted directly here; embedded sub-protocols own
    /// their own internal transcripts and fold independently.
    transcript: blake3::Hasher,

    /// Addresses whose post-teardown state is returned.
    export_addrs: RangeSet<usize>,

    /// Wires at `export_addrs` addresses.
    state_dump: Option<Vec<Wire<F>>>,
}

impl<RV, F, B, Strat> Verifier<RV, F, B, Strat>
where
    Strat: VerifierStrategy<F, Wire = Wire<F>>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLESender<F>,
    F: Field,
    B: PermVerifierBackend<F, F>,
{
    /// Construct an empty RAM verifier.
    ///
    /// # Arguments
    ///
    /// * `config` — protocol config.
    /// * `clock` — clock strategy .
    /// * `rvole` — random VOLE sender.
    /// * `mul_vole` — derandomized VOLE sender (for multiplication protocol).
    /// * `mul_rvole` — random VOLE sender (for multiplication protocol).
    /// * `perm_verifier` — permutation-proof verifier.
    /// * `set_verifier` — set-membership verifier.
    pub fn new(
        config: Config<F, Strat>,
        clock: Strat::Clock,
        rvole: RV,
        mul_vole: DerandVOLESender<RV, F>,
        mul_rvole: RV,
        perm_verifier: PermVerifier<F, F, B>,
        set_verifier: set::Verifier<RV, F, B, Strat>,
    ) -> Result<Self, Error> {
        let Config {
            live_addrs,
            value_bits,
            total_accesses,
            export_addrs,
            ..
        } = config;
        let address_bound = live_addrs
            .end()
            .expect("Config::build rejects an empty live_addrs");
        let l_addr = Strat::wire_length_for(address_bound);
        let l_val = Strat::wire_length_for_log2(value_bits);
        let delta = rvole.delta();

        Ok(Self {
            l_addr,
            l_val,
            live_addrs,
            total_accesses,
            accesses_performed: 0,
            state: State::Initialized,
            delta,
            clock,
            vole: DerandVOLESender::new(rvole),
            perm_verifier,
            set_verifier,
            mux_mul_verifier: MuxMulVerifier::new(
                mul_rvole,
                mul_vole,
                Strat::BOOLEAN_CHECK_ENABLED,
            ),
            pending_accesses: Vec::new(),
            reads: Vec::new(),
            writes: Vec::new(),
            transcript: blake3::Hasher::new(),
            export_addrs,
            state_dump: None,
        })
    }

    /// Allocates resources. Must be called exactly once.
    pub fn alloc(&mut self) -> Result<(), Error> {
        if self.state != State::Initialized {
            return Err(Error::WrongState(self.state));
        }
        // Per access we input-gate `(val_old, t_old)` — `l_val +
        // l_clock` VOLEs each. Plus one such input-gating pass per
        // live cell at teardown for the per-cell final read.
        // Total VOLEs: `(T + live_count) · (l_val + l_clock)`.
        let live_count = self.live_addrs.len();
        let l_clock = self.clock.l_clock();
        let ram_vole_count = (self.total_accesses + live_count) * (self.l_val + l_clock);
        self.vole.alloc(ram_vole_count).map_err(Error::DerandVole)?;
        self.perm_verifier
            .alloc(live_count + self.total_accesses)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        // Set: T lookups (one per access). The set_size = T was
        // baked into set_prover at its own construction.
        self.set_verifier
            .alloc(self.total_accesses)
            .map_err(|e| Error::Set(Box::new(e)))?;

        // MuxMul: one product per access.
        self.mux_mul_verifier
            .alloc(self.total_accesses * self.l_val)
            .map_err(|e| Error::MuxMul(Box::new(e)))?;

        self.state = State::Allocated;
        Ok(())
    }

    /// Initialize RAM with cleartext initial content.
    ///
    /// `values` must have length `live_addrs.len()`: one value per
    /// address in [`Config::live_addrs`].
    pub fn setup(&mut self, values: Vec<Vec<Strat::S>>) -> Result<(), Error> {
        if values.len() != self.live_addrs.len() {
            return Err(Error::LengthMismatch);
        }
        let wired: Vec<Wire<F>> = values
            .into_iter()
            .map(|val| Wire::constant(&val, self.delta))
            .collect();
        self.setup_with_wires(wired)
    }

    /// Initialize RAM with pre-authenticated initial content.
    ///
    /// `values` must have length `live_addrs.len()`: one value per
    /// address in [`Config::live_addrs`].
    pub fn setup_with_wires(&mut self, values: Vec<Wire<F>>) -> Result<(), Error> {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if values.len() != self.live_addrs.len() {
            return Err(Error::LengthMismatch);
        }
        self.writes.reserve(values.len());

        let clock0 = self.clock_packed();

        for (addr, val) in self.live_addrs.iter_values().zip(values) {
            if val.len() != self.l_val {
                return Err(Error::LengthMismatch);
            }
            let idx = addr as u32;
            let addr_cleartext = Strat::index_to_bundle(idx, self.l_addr);
            let addr: Wire<F> = Wire::constant(&addr_cleartext, self.delta);

            self.writes.push(Record {
                addr: addr.pack::<Strat::S>(),
                val: val.pack::<Strat::S>(),
                clock: clock0,
            });
        }

        // Initialize the set with the valid {1..T} set.
        let set_members = self.clock.valid_deltas();
        self.set_verifier
            .setup(set_members)
            .map_err(|e| Error::Set(Box::new(e)))?;

        self.state = State::Setup;
        Ok(())
    }

    /// Record a memory access.
    ///
    /// Computes the multiplexer `new = old + op · (w − old)` and
    /// emits the corresponding records, so:
    ///   - op = 0 ⇒ new = old (value preserved)
    ///   - op = 1 ⇒ new = w   (value overwritten)
    ///
    /// # Arguments
    ///
    /// * `op` — operation: `0` for load or `1` for store.
    /// * `addr` — target cell's address.
    /// * `w` — would-be-stored value on the `op = 1` branch (ignored at `op =
    ///   0`, but still committed).
    pub fn access(&mut self, op: Wire<F>, addr: Wire<F>, w: Wire<F>) -> Result<(), Error> {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        if op.len() != 1 || addr.len() != self.l_addr || w.len() != self.l_val {
            return Err(Error::LengthMismatch);
        }
        if self.accesses_performed >= self.total_accesses {
            return Err(Error::TooManyAccesses);
        }
        self.accesses_performed += 1;
        self.pending_accesses.push(PendingAccess {
            op,
            addr: addr.pack::<Strat::S>(),
            w,
        });
        Ok(())
    }

    /// Process the prover's flush message.
    pub fn flush(&mut self, msg: Flush<F>) -> Result<(), Error>
    where
        F: Copy + Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        let num_accesses = self.pending_accesses.len();
        if msg.access_adj.len() != num_accesses {
            return Err(Error::LengthMismatch);
        }
        if msg.mul_flush.adjustments.len() != num_accesses {
            return Err(Error::LengthMismatch);
        }

        let Flush {
            access_adj: ram_access_adjustments,
            mul_flush,
        } = msg;

        let l_clock = self.clock.l_clock();

        // Prepare the values to compute the per-access multiplexer `new = old + op ·
        // diff`, where diff = ( w - old).
        let mut olds: Vec<Wire<F>> = Vec::with_capacity(num_accesses);
        let mut ops: Vec<Wire<F>> = Vec::with_capacity(num_accesses);
        let mut diffs: Vec<Wire<F>> = Vec::with_capacity(num_accesses);
        let mut addrs: Vec<PackedWire<F>> = Vec::with_capacity(num_accesses);
        let mut t_olds: Vec<Wire<F>> = Vec::with_capacity(num_accesses);

        for (adj, access) in ram_access_adjustments
            .iter()
            .zip(std::mem::take(&mut self.pending_accesses).into_iter())
        {
            if adj.diffs.len() != self.l_val + l_clock {
                return Err(Error::LengthMismatch);
            }
            self.transcript
                .update(&bcs::to_bytes(adj).expect("serialize"));

            let PendingAccess { op, addr, w } = access;

            // Two derand pulls: val_old, then t_old.
            let val_old: Wire<F> = self
                .vole
                .adjust(&VoleAdjustment {
                    diffs: adj.diffs[..self.l_val].to_vec(),
                })
                .map_err(Error::DerandVole)?
                .into();
            let t_old: Wire<F> = self
                .vole
                .adjust(&VoleAdjustment {
                    diffs: adj.diffs[self.l_val..].to_vec(),
                })
                .map_err(Error::DerandVole)?
                .into();

            diffs.push(Strat::sub_wires(&w, &val_old));
            ops.push(op);
            addrs.push(addr);
            olds.push(val_old);
            t_olds.push(t_old);
        }

        // Batch-multiply op · diff.
        let prod_wires = self
            .mux_mul_verifier
            .accumulate(&ops, &diffs, &mul_flush)
            .map_err(|e| Error::MuxMul(Box::new(e)))?;

        // Complete the access: advance clock, push records.
        for (((addr, old), t_old), prod) in addrs
            .into_iter()
            .zip(olds.into_iter())
            .zip(t_olds.into_iter())
            .zip(prod_wires.into_iter())
        {
            let new = Strat::add_wires(&old, &prod);

            self.reads.push(Record {
                addr,
                val: old.pack::<Strat::S>(),
                clock: t_old.pack::<Strat::S>(),
            });

            self.clock.next_clock();
            self.writes.push(Record {
                addr,
                val: new.pack::<Strat::S>(),
                clock: self.clock_packed(),
            });

            let delta = self.clock.compute_delta(&t_old, self.delta);
            self.set_verifier
                .lookup(delta)
                .map_err(|e| Error::Set(Box::new(e)))?;
        }

        Ok(())
    }

    /// Process the prover's pre-teardown message.
    ///
    /// If any unflushed accesses exist, the caller is responsible for
    /// calling [`flush`](Self::flush) before this method.
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`setup_with_wires`](Self::setup_with_wires) or to
    /// [`access`](Self::access) before this call — otherwise the
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
        if !self.pending_accesses.is_empty() {
            return Err(Error::UnflushedAdjustments {
                pending: self.pending_accesses.len(),
            });
        }

        // Absorb into the internal transcript.
        self.transcript
            .update(&bcs::to_bytes(&msg.teardown_adj).expect("serialize"));

        // Per-cell derand.
        let stride = self.l_val + self.clock.l_clock();
        let expected = self.live_addrs.len() * stride;
        if msg.teardown_adj.diffs.len() != expected {
            return Err(Error::LengthMismatch);
        }
        let mut state_dump = Vec::with_capacity(self.export_addrs.len());
        for (pos, i) in self.live_addrs.iter_values().enumerate() {
            let idx = i as u32;
            let base = pos * stride;

            let val_keys = self
                .vole
                .adjust(&VoleAdjustment {
                    diffs: msg.teardown_adj.diffs[base..base + self.l_val].to_vec(),
                })
                .map_err(Error::DerandVole)?;

            let t_keys = self
                .vole
                .adjust(&VoleAdjustment {
                    diffs: msg.teardown_adj.diffs[base + self.l_val..base + stride].to_vec(),
                })
                .map_err(Error::DerandVole)?;

            let addr_bundle = Strat::index_to_bundle(idx, self.l_addr);
            let addr: Wire<F> = Wire::constant(&addr_bundle, self.delta);

            if self.export_addrs.contains(&i) {
                state_dump.push(Wire::new(val_keys.clone().into()));
            }

            self.reads.push(Record {
                addr: addr.pack::<Strat::S>(),
                val: PackedWire::pack::<Strat::S>(&val_keys),
                clock: PackedWire::pack::<Strat::S>(&t_keys),
            });
        }
        self.state_dump = Some(state_dump);

        // Fold the protocol-internal transcript.
        transcript.update(self.transcript.finalize().as_bytes());

        let read_keys: Vec<Vec<F>> = self.reads.iter().map(|r| r.to_keys()).collect();
        let write_keys: Vec<Vec<F>> = self.writes.iter().map(|r| r.to_keys()).collect();

        // perm-proof phase 1: prepare.
        self.perm_verifier
            .prepare(transcript, &read_keys, &write_keys, msg.preparation)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        self.set_verifier
            .teardown_prepare(transcript, msg.set)
            .map_err(|e| Error::Set(Box::new(e)))?;

        self.state = State::TeardownPrepared;
        Ok(())
    }

    /// Tear down the instance, verifying the prover message and returning the
    /// cell values at [`Config::export_addrs`].
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`setup_with_wires`](Self::setup_with_wires) or to
    /// [`access`](Self::access) before this call — otherwise the
    /// protocol's soundness guarantee no longer holds.
    pub fn teardown(
        mut self,
        transcript: &mut blake3::Hasher,
        msg: TeardownMsg<F, B::BackendProof>,
    ) -> Result<Vec<Wire<F>>, Error>
    where
        F: Copy + Serialize + zerocopy::IntoBytes + zerocopy::FromBytes,
        B::BackendProof: Serialize,
    {
        if self.state != State::TeardownPrepared {
            return Err(Error::WrongState(self.state));
        }
        let state_dump = self
            .state_dump
            .take()
            .expect("state_dump populated at teardown_prepare");
        let Self {
            perm_verifier,
            set_verifier,
            mux_mul_verifier,
            ..
        } = self;

        // Verify all sub proofs.
        perm_verifier
            .verify(msg.ram_proof, transcript)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        set_verifier
            .teardown(msg.set, transcript)
            .map_err(|e| Error::Set(Box::new(e)))?;

        mux_mul_verifier
            .finalize(transcript, &msg.mul_proof.qs_proof)
            .map_err(|e| Error::MuxMul(Box::new(e)))?;

        Ok(state_dump)
    }

    /// Pack the current clock.
    fn clock_packed(&self) -> PackedWire<F> {
        let bits = self.clock.current_clock();
        let wire: Wire<F> = Wire::constant(bits, self.delta);
        wire.pack::<Strat::S>()
    }
}

/// Pending access.
struct PendingAccess<F> {
    /// Operation.
    op: Wire<F>,
    /// Target cell's address.
    addr: PackedWire<F>,
    /// New value.
    w: Wire<F>,
}

/// Lifecycle state for the [`Verifier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initialized.
    Initialized,
    /// Allocated.
    Allocated,
    /// Setup.
    Setup,
    /// Teardown-prepared.
    TeardownPrepared,
}

impl<F: Copy> Record<PackedWire<F>> {
    /// Decompose into per-slot keys in `addr, val, clock` order.
    fn to_keys(&self) -> Vec<F> {
        vec![self.addr.key, self.val.key, self.clock.key]
    }
}

/// RAM verifier error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Bundle length mismatch or wrong adjustment count.
    #[error("bundle length mismatch")]
    LengthMismatch,

    /// More accesses requested than the verifier was sized for.
    #[error("access count exceeded total_accesses")]
    TooManyAccesses,

    /// A method was called while the verifier was in the wrong
    /// lifecycle state.
    #[error("ram verifier method called from wrong state: {0:?}")]
    WrongState(State),

    /// [`teardown_prepare`](Verifier::teardown_prepare) called while
    /// per-access pending data had not been drained by
    /// [`flush`](Verifier::flush).
    #[error("teardown_prepare called with {pending} unflushed accesses")]
    UnflushedAdjustments {
        /// Number of accesses still queued.
        pending: usize,
    },

    /// Derandomized VOLE sender error.
    #[error("derand VOLE error: {0}")]
    DerandVole(#[source] DerandVOLESenderError),

    /// Permutation-proof error.
    #[error("permutation-proof error: {0}")]
    PermProof(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Set-membership error.
    #[error("set-membership error: {0}")]
    Set(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Mux-multiplication error.
    #[error("mux-mul error: {0}")]
    MuxMul(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}
