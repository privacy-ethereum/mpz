//! Prover side of the RAM protocol.

use mpz_common::future::Output;
use mpz_fields::Field;
use mpz_perm_proof_core::{Prover as PermProver, backend::ProverBackend as PermProverBackend};
use mpz_poly_proof_core::ExtensionField;
use mpz_vole_core::{
    DerandVOLEReceiver, DerandVOLEReceiverError, RVOLEReceiver, VOLEReceiver, VoleAdjustment,
};

use super::{Flush, Record, TeardownMsg, TeardownPrepare, mux_mul::MuxMulProver};
use serde::Serialize;

use super::{
    clock::{Clock, ProverClock},
    config::Config,
    strategy::ProverStrategy,
};
use crate::{
    set,
    wire::{Bundle, PackedProverWire, ProverWire as Wire},
};
use rangeset::set::RangeSet;

/// RAM prover.
pub struct Prover<RV, F, B, Strat>
where
    Strat: ProverStrategy<F>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLEReceiver<Strat::S, F>,
    F: Field,
    B: PermProverBackend<F, F>,
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
    /// Lifecycle state.
    state: State,

    /// Clock strategy.
    clock: Strat::Clock,

    /// Derandomized VOLE receiver.
    vole: DerandVOLEReceiver<RV, Strat::S, F>,

    /// Permutation protocol prover.
    perm_prover: PermProver<F, F, B>,

    /// Set-membership prover.
    set_prover: set::Prover<RV, F, B, Strat>,

    /// Mux-multiplication prover.
    mux_mul_prover: MuxMulProver<RV, RV, Strat::S, F>,

    /// Cleartext shadow indexed by the address's integer form.
    shadow: Vec<Option<ShadowEntry<Strat::S>>>,

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

    /// Addresses whose post-teardown state is returned.
    export_addrs: RangeSet<usize>,

    /// Wires at `export_addrs` addresses.
    state_dump: Option<Vec<Wire<Strat::S, F>>>,
}

impl<RV, F, B, Strat> Prover<RV, F, B, Strat>
where
    Strat: ProverStrategy<F, Wire = Wire<<Strat as crate::strategy::FieldStrategy<F>>::S, F>>,
    F: ExtensionField<Strat::S> + ExtensionField<F>,
    RV: RVOLEReceiver<Strat::S, F>,
    F: Field,
    B: PermProverBackend<F, F>,
{
    /// Construct an empty RAM prover.
    ///
    /// # Arguments
    ///
    /// * `config` — protocol config.
    /// * `clock` — clock strategy.
    /// * `vole` — derandomized VOLE receiver.
    /// * `mul_vole` — derandomized VOLE receiver (for multiplication protocol).
    /// * `mul_rvole` — random VOLE receiver (for multiplication protocol).
    /// * `perm_prover` — permutation protocol prover.
    /// * `set_prover` — set-membership prover.
    pub fn new(
        config: Config<F, Strat>,
        clock: Strat::Clock,
        vole: DerandVOLEReceiver<RV, Strat::S, F>,
        mul_vole: DerandVOLEReceiver<RV, Strat::S, F>,
        mul_rvole: RV,
        perm_prover: PermProver<F, F, B>,
        set_prover: set::Prover<RV, F, B, Strat>,
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
        let mut shadow = Vec::with_capacity(address_bound);
        shadow.resize_with(address_bound, || None);

        Ok(Self {
            l_addr,
            l_val,
            live_addrs,
            total_accesses,
            accesses_performed: 0,
            state: State::Initialized,
            clock,
            vole,
            perm_prover,
            set_prover,
            mux_mul_prover: MuxMulProver::new(mul_rvole, mul_vole, Strat::BOOLEAN_CHECK_ENABLED),
            shadow,
            reads: Vec::new(),
            writes: Vec::new(),
            pending_adjustments: Vec::new(),
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
        self.vole.alloc(ram_vole_count).map_err(Error::Vole)?;
        self.perm_prover
            .alloc(live_count + self.total_accesses)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        // Set: T lookups (one per access). The set_size = T was
        // baked into set_prover at its own construction.
        self.set_prover
            .alloc(self.total_accesses)
            .map_err(|e| Error::Set(Box::new(e)))?;

        // MuxMul: one product per access.
        self.mux_mul_prover
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
        let wired: Vec<Wire<Strat::S, F>> = values.into_iter().map(Wire::constant).collect();
        self.setup_with_wires(wired)
    }

    /// Initialize RAM with pre-authenticated initial content.
    ///
    /// `values` must have length `live_addrs.len()`: one value per
    /// address in [`Config::live_addrs`].
    pub fn setup_with_wires(&mut self, values: Vec<Wire<Strat::S, F>>) -> Result<(), Error> {
        if self.state != State::Allocated {
            return Err(Error::WrongState(self.state));
        }
        if values.len() != self.live_addrs.len() {
            return Err(Error::LengthMismatch);
        }
        self.writes.reserve(values.len());

        let clock_cleartext: Bundle<Strat::S> = self.clock.current_clock().clone();
        let clock0_wire: Wire<Strat::S, F> = Wire::constant(clock_cleartext.clone());
        let clock0_wire = (&clock0_wire).into();

        for (addr, val_input) in self.live_addrs.iter_values().zip(values) {
            if val_input.len() != self.l_val {
                return Err(Error::LengthMismatch);
            }
            let idx = addr as u32;
            let addr_wire = addr_wire_for_index::<Strat, F>(idx, self.l_addr);
            let val_cleartext = val_input.value().clone();
            let val_wire = (&val_input).into();

            self.shadow[addr] = Some(ShadowEntry {
                value: val_cleartext,
                last_clock: clock_cleartext.clone(),
            });

            self.writes.push(Record {
                addr: addr_wire,
                val: val_wire,
                clock: clock0_wire,
            });
        }

        // Initialize the set with the valid {1..T} set.
        let set_members = self.clock.valid_deltas();
        self.set_prover
            .setup(set_members)
            .map_err(|e| Error::Set(Box::new(e)))?;

        self.state = State::Setup;
        Ok(())
    }

    /// Perform a memory access, returning the new value (= `old` on load, `w`
    /// on store, by construction).
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
    pub fn access(
        &mut self,
        op: Wire<Strat::S, F>,
        addr: Wire<Strat::S, F>,
        w: Wire<Strat::S, F>,
    ) -> Result<Wire<Strat::S, F>, Error>
    where
        F: Copy + serde::Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        // Length validation. op is a single authenticated value;
        // addr matches l_addr; w matches l_val.
        if op.len() != 1 {
            return Err(Error::LengthMismatch);
        }
        if addr.len() != self.l_addr {
            return Err(Error::LengthMismatch);
        }
        if w.len() != self.l_val {
            return Err(Error::LengthMismatch);
        }
        if self.accesses_performed >= self.total_accesses {
            return Err(Error::TooManyAccesses);
        }

        // Shadow lookup.
        let idx = Strat::bundle_to_index(addr.value());
        let entry = self
            .shadow
            .get(idx as usize)
            .and_then(|slot| slot.as_ref())
            .ok_or(Error::AddressNotFound)?;
        let val_old_cleartext = entry.value.clone();
        let t_old_cleartext = entry.last_clock.clone();
        let addr = (&addr).into();

        // Input-gate (val_old, t_old). Queue both, run adjust to
        // resolve the futures, then receive macs.
        let mut val_fut = self
            .vole
            .queue_recv_vole(&val_old_cleartext)
            .map_err(Error::Vole)?;
        let mut t_fut = self
            .vole
            .queue_recv_vole(&t_old_cleartext)
            .map_err(Error::Vole)?;
        let adjustment = self.vole.adjust().map_err(Error::Vole)?;
        let val_macs: Vec<F> = val_fut
            .try_recv()
            .map_err(|_| Error::VoleFutureUnresolved)?
            .ok_or(Error::VoleFutureUnresolved)?
            .macs;
        let t_macs: Vec<F> = t_fut
            .try_recv()
            .map_err(|_| Error::VoleFutureUnresolved)?
            .ok_or(Error::VoleFutureUnresolved)?
            .macs;

        let val_old = Wire::new(val_old_cleartext.clone(), val_macs.into());
        let t_old = Wire::new(t_old_cleartext, t_macs.into());

        // Absorb the adjustment into the prover-internal transcript.
        self.transcript
            .update(&bcs::to_bytes(&adjustment).expect("serialize"));
        self.pending_adjustments.push(adjustment);

        // Append read record.
        self.reads.push(Record {
            addr,
            val: (&val_old).into(),
            clock: (&t_old).into(),
        });

        // 4. Advance clock.
        self.accesses_performed += 1;
        self.clock.next_clock();
        let new_clock_cleartext: Bundle<Strat::S> = self.clock.current_clock().clone();
        // Clock value is public.
        let new_clock: Wire<Strat::S, F> = Wire::constant(new_clock_cleartext.clone());

        // Mux: new = val_old + op · (w − val_old).
        //    diff = w − val_old
        //    prod = op · diff
        //    new  = val_old + prod
        let diff = Strat::sub_wires(&w, &val_old);
        let prod = self
            .mux_mul_prover
            .accumulate(&op, &diff)
            .map_err(|e| Error::MuxMul(Box::new(e)))?;
        let new_val = Strat::add_wires(&val_old, &prod);

        self.writes.push(Record {
            addr,
            val: (&new_val).into(),
            clock: (&new_clock).into(),
        });

        // Set membership: delta = current_clock − t_old.
        let delta = self.clock.compute_delta(&t_old);
        self.set_prover
            .lookup(delta)
            .map_err(|e| Error::Set(Box::new(e)))?;

        // Update shadow.
        let entry = self.shadow[idx as usize]
            .as_mut()
            .expect("shadow entry must still exist after access");
        entry.value = new_val.value().clone();
        entry.last_clock = new_clock_cleartext;

        Ok(new_val)
    }

    /// Emit a flush message.
    ///
    /// May be called any number of times during the access phase.
    pub fn flush(&mut self) -> Result<Flush<F>, Error>
    where
        F: Copy,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        let mul_flush = self
            .mux_mul_prover
            .flush()
            .map_err(|e| Error::MuxMul(Box::new(e)))?;
        Ok(Flush {
            access_adj: std::mem::take(&mut self.pending_adjustments),
            mul_flush,
        })
    }

    /// Emit a pre-`teardown` message.
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
    ) -> Result<TeardownPrepare<F, B::Preparation>, Error>
    where
        F: Copy + Serialize,
    {
        if self.state != State::Setup {
            return Err(Error::WrongState(self.state));
        }
        if !self.pending_adjustments.is_empty() {
            return Err(Error::UnflushedAdjustments {
                pending: self.pending_adjustments.len(),
            });
        }
        // Per-address teardown reads with fresh input-gated
        // (val_final, t_final), over the live cells.
        let teardown_data: Vec<(u32, PackedProverWire<F>, Bundle<Strat::S>, Bundle<Strat::S>)> =
            self.live_addrs
                .iter_values()
                .map(|addr| {
                    let idx = addr as u32;
                    let entry = self.shadow[addr]
                        .as_ref()
                        .expect("every live cell is populated at setup");
                    (
                        idx,
                        addr_wire_for_index::<Strat, F>(idx, self.l_addr),
                        entry.value.clone(),
                        entry.last_clock.clone(),
                    )
                })
                .collect();

        let mut futs = Vec::with_capacity(teardown_data.len());
        for (_, _, val_cleartext, t_cleartext) in &teardown_data {
            let val_fut = self
                .vole
                .queue_recv_vole(val_cleartext)
                .map_err(Error::Vole)?;
            let t_fut = self
                .vole
                .queue_recv_vole(t_cleartext)
                .map_err(Error::Vole)?;
            futs.push((val_fut, t_fut));
        }

        let teardown_adj = self.vole.adjust().map_err(Error::Vole)?;
        self.transcript
            .update(&bcs::to_bytes(&teardown_adj).expect("serialize"));

        let mut state_dump: Vec<Wire<Strat::S, F>> = Vec::with_capacity(self.export_addrs.len());
        for ((idx, addr_wire, val_cleartext, t_cleartext), (mut val_fut, mut t_fut)) in
            teardown_data.into_iter().zip(futs)
        {
            let val_macs: Vec<F> = val_fut
                .try_recv()
                .map_err(|_| Error::VoleFutureUnresolved)?
                .ok_or(Error::VoleFutureUnresolved)?
                .macs;
            let t_macs: Vec<F> = t_fut
                .try_recv()
                .map_err(|_| Error::VoleFutureUnresolved)?
                .ok_or(Error::VoleFutureUnresolved)?
                .macs;

            let val_wire = Wire::new(val_cleartext, val_macs.into());
            let t_wire = Wire::new(t_cleartext, t_macs.into());

            self.reads.push(Record {
                addr: addr_wire,
                val: (&val_wire).into(),
                clock: (&t_wire).into(),
            });

            if self.export_addrs.contains(&(idx as usize)) {
                state_dump.push(val_wire);
            }
        }
        self.state_dump = Some(state_dump);

        // Fold the protocol-internal transcript.
        transcript.update(self.transcript.finalize().as_bytes());

        // perm-proof phase 1: prepare.
        let (read_values, read_macs): (Vec<Vec<F>>, Vec<Vec<F>>) =
            self.reads.iter().map(|r| r.to_parts()).unzip();
        let (write_values, write_macs): (Vec<Vec<F>>, Vec<Vec<F>>) =
            self.writes.iter().map(|r| r.to_parts()).unzip();

        let preparation = self
            .perm_prover
            .prepare(
                transcript,
                (&read_values, &read_macs),
                (&write_values, &write_macs),
            )
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        let set_prepare = self
            .set_prover
            .teardown_prepare(transcript)
            .map_err(|e| Error::Set(Box::new(e)))?;

        self.state = State::TeardownPrepared;
        Ok(TeardownPrepare {
            teardown_adj,
            preparation,
            set: set_prepare,
        })
    }

    /// Tear down the instance, returning the message to be sent to
    /// the verifier and the cell values at [`Config::export_addrs`].
    ///
    /// `transcript` is the caller's transcript. The caller is
    /// responsible for having already absorbed every wire that was
    /// fed as an input to [`setup_with_wires`](Self::setup_with_wires) or to
    /// [`lookup`](Self::lookup) before this call — otherwise the
    /// protocol's soundness guarantee no longer holds.
    pub fn teardown(
        mut self,
        transcript: &mut blake3::Hasher,
    ) -> Result<(TeardownMsg<F, B::BackendProof>, Vec<Wire<Strat::S, F>>), Error>
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
            .expect("teardown_prepare populates state_dump");
        let Self {
            perm_prover,
            set_prover,
            mux_mul_prover,
            ..
        } = self;

        // Finalize all sub proofs.
        let proof = perm_prover
            .prove(transcript)
            .map_err(|e| Error::PermProof(Box::new(e)))?;

        let set_msg = set_prover
            .teardown(transcript)
            .map_err(|e| Error::Set(Box::new(e)))?;

        let mul_proof = mux_mul_prover
            .finalize(transcript)
            .map_err(|e| Error::MuxMul(Box::new(e)))?;

        Ok((
            TeardownMsg {
                ram_proof: proof,
                set: set_msg,
                mul_proof,
            },
            state_dump,
        ))
    }
}

/// Per-address shadow entry.
struct ShadowEntry<S> {
    /// Value at the address slot.
    value: Bundle<S>,
    /// Clock value at the time of the most recent access.
    last_clock: Bundle<S>,
}

/// Build the packed prover wire for cell `idx`'s address (a public
/// constant derived from the cell's index).
fn addr_wire_for_index<Strat, F>(idx: u32, l_addr: usize) -> PackedProverWire<F>
where
    Strat: ProverStrategy<F>,
    F: Field + ExtensionField<Strat::S> + ExtensionField<F>,
{
    let addr_bundle = Strat::index_to_bundle(idx, l_addr);
    let addr_input: Wire<Strat::S, F> = Wire::constant(addr_bundle);
    (&addr_input).into()
}

impl<F: Copy> Record<PackedProverWire<F>> {
    /// Decompose into `(values, macs)` slot vectors in `addr, val,
    /// clock` order.
    fn to_parts(&self) -> (Vec<F>, Vec<F>) {
        (
            vec![self.addr.value, self.val.value, self.clock.value],
            vec![self.addr.mac, self.val.mac, self.clock.mac],
        )
    }
}

/// Lifecycle state for the [`Prover`].
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

/// RAM prover error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Address not registered in the shadow.
    #[error("address not found in RAM shadow")]
    AddressNotFound,

    /// More accesses requested than the prover was sized for.
    #[error("access count exceeded total_accesses")]
    TooManyAccesses,

    /// A method was called while the prover was in the wrong
    /// lifecycle state .
    #[error("ram prover method called from wrong state: {0:?}")]
    WrongState(State),

    /// [`teardown_prepare`](Prover::teardown_prepare) called while
    /// per-access adjustments were still pending.
    #[error("teardown_prepare called with {pending} unflushed adjustments")]
    UnflushedAdjustments {
        /// Number of adjustments still queued.
        pending: usize,
    },

    /// Bundle length mismatch between configured and actual.
    #[error("bundle length mismatch")]
    LengthMismatch,

    /// Underlying VOLE receiver error.
    #[error("VOLE error: {0}")]
    Vole(#[source] DerandVOLEReceiverError),

    /// VOLE future failed to resolve after `adjust`.
    #[error("VOLE future failed to resolve after adjust")]
    VoleFutureUnresolved,

    /// Permutation-proof error during teardown.
    #[error("permutation-proof error: {0}")]
    PermProof(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Embedded set-membership error.
    #[error("set-membership error: {0}")]
    Set(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Mux-multiplication sub-proof error.
    #[error("mux-mul error: {0}")]
    MuxMul(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use crate::{
        ram::MultiplicativeClock,
        strategy::{Char2Strategy, FieldStrategy, version::MultiplicativeStep},
        test_utils::{bits, prover_wire},
    };
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};
    use mpz_perm_proof_core::test_utils::build_ideal_perm_proof_pair;
    use mpz_vole_core::ideal::rvole::ideal_rvole;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// The cleartext RAM model: `access` returns the right value (store
    /// → `w`, load → the cell's current value), and the prover's shadow
    /// ends in the correct state — read-after-write holds, loads do not
    /// mutate, and cells stay independent.
    #[test]
    fn access_cleartext_ram_semantics() {
        const MEMORY_SIZE: usize = 3;
        const VALUE_BITS: usize = 4;
        const FAN_IN: usize = 8;

        // Access script: (addr index, op bit, would-be-stored value).
        let script = [
            (2usize, true, 0b1010u64), // store 0b1010 → addr 2
            (2, false, 0b0000),        // load addr 2  → read-after-write
            (1, false, 0b0000),        // load addr 1  → untouched setup value
            (0, true, 0b0101),         // store 0b0101 → addr 0
            (2, false, 0b0000),        // load addr 2  → unaffected by store to 0
        ];
        let t = script.len();

        let mut rng = StdRng::seed_from_u64(0x4a17);
        let delta: Gf2_64 = rng.random();

        // Sizing — mirrors `alloc`.
        let clock = MultiplicativeClock::new(t).expect("clock");
        let l_clock = clock.l_clock();
        let l_val =
            <Char2Strategy<Gf2_64> as FieldStrategy<Gf2_64>>::wire_length_for_log2(VALUE_BITS);
        let l_addr = <Char2Strategy<Gf2_64> as FieldStrategy<Gf2_64>>::wire_length_for(MEMORY_SIZE);
        let n_ver = l_clock;

        // Derandomized VOLE pools.
        let mk_derand = |seed: u64, count: usize| {
            let (_, mut r) = ideal_rvole::<Gf2, Gf2_64>(seed, delta);
            r.pregenerate(count, delta).expect("pregen");
            DerandVOLEReceiver::new(r)
        };
        let ram_vole = mk_derand(rng.random(), (t + MEMORY_SIZE) * (l_val + l_clock));
        let mul_gate_vole = mk_derand(rng.random(), t * l_val);
        let set_vole = mk_derand(rng.random(), (t + t) * n_ver);

        // Raw RVOLE for the mux VOPE — reserved by `alloc`, consumed
        // only at finalize (never reached here).
        let vope_count = <Gf2_64 as ExtensionField<Gf2>>::MONOMIAL_BASIS.len();
        let (_, mut mul_vope_r) = ideal_rvole::<Gf2, Gf2_64>(rng.random(), delta);
        mul_vope_r
            .pregenerate(vope_count, delta)
            .expect("vope pregen");

        // Perm-proof provers.
        let (ram_perm, _) = build_ideal_perm_proof_pair(&mut rng, delta, MEMORY_SIZE + t, FAN_IN);
        let (set_perm, _) = build_ideal_perm_proof_pair(&mut rng, delta, t + t, FAN_IN);

        let set_prover = crate::set::Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
            t,
            MultiplicativeStep::new(n_ver).expect("version step"),
            set_vole,
            set_perm,
        )
        .expect("set prover");

        let config = Config::<Gf2_64, Char2Strategy<Gf2_64>>::builder(
            RangeSet::from(0..MEMORY_SIZE),
            VALUE_BITS,
            t,
        )
        .build()
        .expect("config");

        let mut prover = Prover::<_, _, _, Char2Strategy<Gf2_64>>::new(
            config,
            clock,
            ram_vole,
            mul_gate_vole,
            mul_vope_r,
            ram_perm,
            set_prover,
        )
        .expect("prover");
        prover.alloc().expect("alloc");

        // Setup: one value per cell, in address order.
        let setup = vec![
            bits(0b0011, l_val),
            bits(0b1100, l_val),
            bits(0b0110, l_val),
        ];
        let mut model = setup.clone(); // cleartext memory model
        prover.setup(setup).expect("setup");

        // Drive the script, asserting each access's returned value.
        for (addr_idx, op_bit, w_val) in script {
            let op = prover_wire(vec![Gf2(op_bit)]);
            let addr = prover_wire(bits(addr_idx as u64, l_addr));
            let w = prover_wire(bits(w_val, l_val));

            let returned = prover.access(op, addr, w).expect("access");

            // Store → w; load → the cell's current value.
            let expected = if op_bit {
                bits(w_val, l_val)
            } else {
                model[addr_idx].clone()
            };
            assert_eq!(
                returned.value().as_slice(),
                expected.as_slice(),
                "access(addr={addr_idx}, op={op_bit}) returned the wrong value",
            );
            model[addr_idx] = expected; // store updates the model; load is a no-op
        }

        // Final shadow must match the model.
        for (idx, want) in model.iter().enumerate() {
            let got = prover.shadow[idx].as_ref().expect("cell populated");
            assert_eq!(
                got.value.as_slice(),
                want.as_slice(),
                "shadow cell {idx} mismatch",
            );
        }
    }
}
