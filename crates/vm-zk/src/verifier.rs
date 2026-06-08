use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_ot_core::rcot::{RCOTSender, RCOTSenderOutput};
use mpz_vm_core::{
    Call, Error as CoreError, Global, Param, Reg, Thread, Visibility, Vm, Write, value::Value,
};
use mpz_vm_ir::{Function, Module};
use rand::Rng;
use rangeset::set::RangeSet;
use serio::{SinkExt, stream::IoStreamExt};
use std::ops::Range;

use mpz_vm_memory::{AuthState, Bit, Registers};

use crate::{
    ChunkOutcome, ProofMessage, VOPE_BITS,
    capture::{self, Role},
    commit::{self, PendingIo, prepare_params},
    error::ZkVmError,
    finalize, host,
    replay::{self, ReplayState},
    reveal,
};

/// A zero-knowledge verifier for an [`mpz-vm-ir`](mpz_vm_ir) [`Module`].
///
/// A `Verifier` checks a [`Prover`](crate::Prover)'s proof that a module was
/// executed correctly against the public inputs and outputs, without learning
/// the witness. It implements the [`Vm`] trait, through which a program is
/// loaded with inputs ([`write`](Vm::write)), run ([`call`](Vm::call)), and
/// queried ([`read`](Vm::read), [`reveal`](Vm::reveal)).
///
/// The type parameter `T` is the correlated-randomness channel shared with the
/// prover.
#[derive(Debug)]
pub struct Verifier<T> {
    module: Module,
    global: Global,
    svole: T,
    pending_io: PendingIo,
    pending_reveal: RangeSet<u32>,
    reveal_state: host::RevealState,
    auth: AuthState,
    zk: mpz_zk_core::Verifier,
    chunk_cap: Option<usize>,
}

impl<T> Verifier<T>
where
    T: RCOTSender<Block>,
{
    /// Creates a verifier for `module` backed by `svole`.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError`] if state for `module` cannot be initialized, or if
    /// `svole` provides a correlation that the protocol cannot use.
    pub fn new(module: Module, svole: T) -> Result<Self, ZkVmError> {
        let global = Global::new(&module)?;
        let delta: Gf2_128 = zerocopy::transmute!(svole.delta());
        // Pointer-bit convention: delta.lsb must be 1 so the per-wire
        // identity `mac.lsb XOR key.lsb == bit * delta.lsb` holds bitwise.
        if delta.to_inner() & 1 != 1 {
            return Err(ZkVmError::DeltaLsb.into());
        }
        let zk = mpz_zk_core::Verifier::new(delta);
        let auth = AuthState::new(Bit(zk.public_bit(false)), Bit(zk.public_bit(true)));
        Ok(Self {
            module,
            global,
            svole,
            pending_io: PendingIo::default(),
            pending_reveal: RangeSet::default(),
            reveal_state: host::RevealState::default(),
            auth,
            zk,
            chunk_cap: None,
        })
    }

    /// Sets the maximum number of operations executed per chunk, returning the
    /// updated verifier.
    ///
    /// A value of `Some(cap)` bounds each chunk to at most `cap` operations,
    /// trading proof granularity against memory use; `None` places no bound.
    /// This must match the prover's setting for the two sides to agree.
    pub fn with_chunk_cap(mut self, cap: Option<usize>) -> Self {
        self.chunk_cap = cap;
        self
    }
}

impl<T> Verifier<T>
where
    T: RCOTSender<Block> + Flush,
{
    #[tracing::instrument(level = "debug", skip(self, io))]
    async fn allocate(
        &mut self,
        io: &mut Context,
        total: usize,
    ) -> Result<Vec<Gf2_128>, ZkVmError> {
        self.svole
            .alloc(total)
            .map_err(|e| ZkVmError::SvoleAlloc(e.to_string()))?;
        self.svole
            .flush(io)
            .await
            .map_err(|e| ZkVmError::SvoleFlush(e.to_string()))?;
        let RCOTSenderOutput { keys, .. } = self
            .svole
            .try_send_rcot(total)
            .map_err(|e| ZkVmError::SvoleIo(e.to_string()))?;
        Ok(keys.into_iter().map(|k| zerocopy::transmute!(k)).collect())
    }
}

impl<T> Vm for Verifier<T>
where
    T: RCOTSender<Block> + Flush,
{
    type Error = ZkVmError;

    /// Writes a value into linear memory at byte offset `ptr`.
    ///
    /// A [`Write::Public`] value is written directly and marked public. A
    /// [`Write::Blind`] reserves `len` bytes of blinded input whose cleartext
    /// the prover holds; the bytes are marked blind and committed on the next
    /// [`call`](Self::call). A [`Write::Private`] is not supported on the
    /// verifier, which never supplies private inputs.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Core`] if the module has no linear
    /// memory. Returns [`ZkVmError::Trap`] if a public write is out of bounds.
    /// Returns [`ZkVmError::Unsupported`] for a [`Write::Private`] value.
    fn write(&mut self, ptr: u32, w: Write<'_>) -> Result<(), ZkVmError> {
        let memory = self
            .global
            .memory_mut()
            .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
        match w {
            Write::Public(data) => {
                memory.write_bytes(ptr, data).map_err(ZkVmError::Trap)?;
                self.global
                    .set_memory_visibility(ptr, data.len(), Visibility::Public);
            }
            Write::Blind(len) => {
                self.pending_io.write_private(ptr, len);
                self.global
                    .set_memory_visibility(ptr, len, Visibility::Blind);
            }
            Write::Private(_) => {
                return Err(ZkVmError::Unsupported(
                    "verifier cannot write private values".into(),
                ));
            }
        }
        Ok(())
    }

    /// Marks the `len` bytes of memory at `ptr` to be opened by the prover.
    ///
    /// The prover's opened cleartext is checked correct on the next
    /// [`call`](Self::call), after which the bytes become readable.
    fn reveal(&mut self, ptr: u32, len: usize) -> Result<(), ZkVmError> {
        self.pending_reveal.union_mut(ptr..ptr + len as u32);
        Ok(())
    }

    /// Returns the `len` bytes of linear memory at byte offset `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Internal`] if the range is tainted, i.e. holds
    /// blinded or not-yet-revealed data whose cleartext the verifier does not
    /// know. Returns [`ZkVmError::Core`] if the module has no linear
    /// memory, or [`ZkVmError::Trap`] if the range is out of bounds.
    fn read(&self, ptr: u32, len: usize) -> Result<&[u8], ZkVmError> {
        if self.global.memory_tainted(ptr, len) {
            return Err(ZkVmError::Internal(format!(
                "cannot read tainted memory at {:#x}",
                ptr
            )));
        }
        let memory = self
            .global
            .memory()
            .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
        memory.read_bytes(ptr, len).map_err(ZkVmError::Trap)
    }

    /// Verifies the prover's proof of the call to function `func_idx` with
    /// `params` over `io`, and returns its result.
    ///
    /// Public computation is reproduced locally, so a function with public
    /// inputs and outputs yields the same value the prover computed. Returns
    /// `Some(value)` when the function yields a value and `None` otherwise.
    /// Pending inputs and reveals are cleared once the call returns.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::InvalidFunction`] if `func_idx` is not a local
    /// function. Returns [`ZkVmError::Trap`] if the proven computation traps
    /// (e.g. divide by zero). Returns a [`ZkVmError`] if verification fails or
    /// communication over `io` fails.
    #[tracing::instrument(level = "info", skip(self, io, params), fields(func_idx, num_params = params.len(), chunk_cap = ?self.chunk_cap))]
    async fn call(
        &mut self,
        io: &mut Context,
        func_idx: u32,
        params: Vec<Param>,
    ) -> Result<Option<Value>, ZkVmError> {
        let func = match self.module.function(func_idx) {
            Some(Function::Local(f)) => f,
            _ => return Err(ZkVmError::Core(CoreError::InvalidFunction(func_idx))),
        };
        let input_bits = prepare_params(&params)?;
        let num_args = params.len() as u32;
        // The root frame's registers begin after its result slot(s), so its
        // parameters occupy absolute registers `root_reg_base + i`. This
        // mirrors `Thread::call`'s layout (results, then params).
        let num_results = func.func_type().results.len() as u32;
        let root_reg_base = Reg(num_results + num_args);

        let mut thread = Thread::new();
        thread.call(
            &self.module,
            &mut self.global,
            Call {
                func_idx,
                params: params.clone(),
            },
        )?;

        // Input + memory commit cost; zeroed after it rides on the
        // first chunk.
        let mut commit_bits = input_bits + self.pending_io.cost_bits();

        self.auth.regs = Registers::new();
        let mut state = ReplayState::root();
        let mut final_output = None;
        let mut chunk_idx: usize = 0;
        // Memory ranges to open on the first proving chunk; mirrors the prover.
        let reveal_ranges: Vec<Range<u32>> = self.pending_reveal.iter().collect();
        let mut reveal_pending = !reveal_ranges.is_empty();
        // Set once a chunk's proof of a public trap verifies.
        let mut trapped: Option<mpz_vm_core::Trap> = None;
        // Mirror of the prover's flag: set once any chunk performs
        // authenticated work, gating the skip of fully public chunks.
        let mut any_zk_work = false;

        loop {
            let chunk_span = tracing::info_span!("verifier.chunk", idx = chunk_idx);
            let _enter = chunk_span.enter();

            // Receive the prover's trap outcome *before* capture: the
            // announced index lets the verifier's Thread resolve its own
            // blocking `Blocked` inline and stop naturally at the trap
            // (no truncation). The prover sent this right after its own
            // capture.
            let outcome: ChunkOutcome = io
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;
            // `trap_at` shapes the proof (the verifier's Thread stop point,
            // the trap-replay pass, skipped output binding) while `trap`
            // is the returned reason; they must be present together or the
            // prover could skip output binding without claiming a trap (or
            // vice versa).
            if outcome.trap_at.is_some() != outcome.trap.is_some() {
                return Err(ZkVmError::Internal(
                    "trap outcome inconsistent: trap_at and trap must agree".into(),
                )
                .into());
            }
            // Merge the announced reveal payloads before capture so the verifier
            // can resolve this chunk's reveals (and any later wait) in lockstep.
            self.reveal_state.merge(outcome.revealed.clone());

            let chunk = capture::capture_chunk(
                &self.module,
                &mut self.global,
                &mut thread,
                self.chunk_cap,
                Role::Verifier,
                outcome.trap_at.zip(outcome.trap.clone()),
                &mut self.reveal_state,
            )?;
            tracing::debug!(
                events = chunk.trace.len(),
                cost = chunk.cost,
                done = chunk.done,
                "captured chunk"
            );

            let execute_bits = commit_bits + chunk.cost;

            // Mirror the prover's skip exactly: a fully public chunk reached
            // before any authenticated work has nothing to prove, so both sides
            // bypass the allocate/commit/challenge/proof exchange in lockstep.
            let needs_zk = execute_bits > 0
                || any_zk_work
                || reveal_pending
                || chunk.trap.as_ref().is_some_and(|t| t.directive.is_some());
            if !needs_zk {
                commit_bits = 0;
                chunk_idx += 1;
                if let Some(point) = &chunk.trap {
                    if outcome.trap.as_ref() != Some(&point.trap) {
                        return Err(ZkVmError::Internal(
                            "announced trap reason does not match proven trap".into(),
                        )
                        .into());
                    }
                    trapped = Some(point.trap.clone());
                    break;
                }
                if chunk.done {
                    // A fully public output is recomputed identically by the
                    // verifier's own Thread, so the result is taken from the
                    // local capture rather than an (unsent) proof message.
                    final_output = chunk.result;
                    break;
                }
                continue;
            }
            any_zk_work = true;

            let total = execute_bits + VOPE_BITS;
            tracing::info!(commit_bits, cost = chunk.cost, total, "cost plan");

            let keys = self.allocate(io, total).await?;
            let (exec_keys, vope_keys) = keys.split_at(execute_bits);
            let vope_keys: &[Gf2_128; VOPE_BITS] =
                vope_keys.try_into().expect("vope tail is VOPE_BITS wide");

            // Receive the prover's commitment to the whole execute tape
            // (commit + gate adjust), then sample and send the challenge.
            let commit_msg: mpz_zk_core::Commit = io
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;
            let adjust: Vec<bool> = commit_msg.adjust.iter().by_vals().collect();
            if adjust.len() != execute_bits {
                return Err(ZkVmError::Internal(format!(
                    "commit adjust short: got {} want {}",
                    adjust.len(),
                    execute_bits
                ))
                .into());
            }
            let chi: [u8; 32] = rand::rng().random();
            io.io_mut()
                .send(chi)
                .await
                .map_err(|e| ZkVmError::IoSend(e.to_string()))?;

            let ProofMessage {
                output,
                revealed,
                proof,
            } = io
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;

            {
                let mut exec = self
                    .zk
                    .execute(exec_keys, &adjust)
                    .map_err(|e| ZkVmError::Internal(e.to_string()))?;
                if commit_bits > 0 {
                    commit::commit_verifier(
                        &mut self.auth,
                        root_reg_base,
                        &params,
                        &self.pending_io,
                        &mut exec,
                    )?;
                }
                replay::replay(
                    &chunk.trace,
                    &chunk.reveal_actions,
                    &self.module,
                    &mut self.auth,
                    &mut exec,
                    &mut state,
                )?;
                match &chunk.trap {
                    // A trapping chunk carries no output to authenticate. When
                    // the trap is tied to a committed op, check its divisor is
                    // zero; a fully public trap has no committed divisor.
                    Some(t) => {
                        if let Some(directive) = &t.directive {
                            replay::replay_trap(directive, &t.trap, &self.auth, &mut exec)?;
                        }
                    }
                    None => {
                        // Only a symbolic return is revealed/authenticated; a
                        // concrete return is already public to both parties.
                        if chunk.result_symbolic {
                            finalize::bind_output(&state, &mut exec, &self.auth, output)?;
                        }
                    }
                }
                // Authenticate the prover's opened cleartext against the
                // committed wires for any pending reveals.
                if reveal_pending {
                    reveal::reveal_verifier(&mut exec, &self.auth, &reveal_ranges, &revealed)?;
                }
                exec.finish()
                    .map_err(|e| ZkVmError::Internal(e.to_string()))?;
            }
            commit_bits = 0;

            self.zk
                .verify(chi, vope_keys, proof)
                .map_err(|_| ZkVmError::BatchCheckFailed)?;

            // The opening verified: write the revealed cleartext into linear
            // memory and drop the ranges' taint so later reads succeed.
            if reveal_pending {
                let mut idx = 0;
                for r in &reveal_ranges {
                    let len = (r.end - r.start) as usize;
                    let memory = self
                        .global
                        .memory_mut()
                        .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
                    memory
                        .write_bytes(r.start, &revealed[idx..idx + len])
                        .map_err(ZkVmError::Trap)?;
                    idx += len;
                    self.global
                        .set_memory_visibility(r.start, len, Visibility::Public);
                }
                reveal_pending = false;
            }
            chunk_idx += 1;
            // Derive the trapped result from `chunk.trap` — the field that
            // actually shaped the proof and caused output binding to be
            // skipped — so a trapped chunk can never fall through to the
            // unbound `final_output = output` branch. The reason is taken
            // from `chunk.trap`, which `capture_chunk` set to the reason
            // proven by the validated trapping directive (divisor==0 =>
            // `Trap::DivideByZero`), so the returned reason is bound to the
            // proof rather than trusting the prover's announcement.
            if let Some(point) = &chunk.trap {
                // `outcome.trap` is the prover's announced reason; it must
                // match the reason actually proven, else the prover claimed
                // a different trap than the constraint attests.
                if outcome.trap.as_ref() != Some(&point.trap) {
                    return Err(ZkVmError::Internal(
                        "announced trap reason does not match proven trap".into(),
                    )
                    .into());
                }
                trapped = Some(point.trap.clone());
                break;
            }
            if chunk.done {
                // A symbolic return was revealed by the prover (`output`); a
                // concrete return is already public, taken from the verifier's
                // own locally-computed result.
                final_output = if chunk.result_symbolic {
                    output
                } else {
                    chunk.result
                };
                break;
            }
        }

        self.pending_io.clear();
        self.pending_reveal = RangeSet::default();
        if let Some(trap) = trapped {
            tracing::info!(chunks = chunk_idx, ?trap, "verifier call trapped");
            return Err(ZkVmError::Trap(trap));
        }
        tracing::info!(chunks = chunk_idx, ?final_output, "verifier call complete");
        Ok(final_output)
    }
}
