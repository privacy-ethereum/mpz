use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_ot_core::rcot::{RCOTReceiver, RCOTReceiverOutput};
use mpz_vm_core::{
    Call, Error as CoreError, Global, Param, Reg, Thread, Visibility, Vm, Write, value::Value,
};
use mpz_vm_ir::{Function, Module};

use mpz_vm_memory::{AuthState, Bit, Registers};
use mpz_zk_core::Commit;
use rangeset::set::RangeSet;
use serio::{SinkExt, stream::IoStreamExt};
use std::ops::Range;

use crate::{
    ChunkOutcome, ProofMessage, VOPE_BITS,
    capture::{self, Role},
    commit::{self, PendingIo, prepare_params},
    error::ZkVmError,
    finalize, host,
    replay::{self, ReplayState},
    reveal,
};

/// A zero-knowledge prover that executes a [`Module`] and proves correct
/// execution to a [`Verifier`](crate::Verifier).
///
/// The prover holds the private witness and produces a proof that the module
/// was executed correctly without revealing that witness. It implements the
/// [`Vm`] trait, through which a program is loaded with inputs ([`write`](Vm::write)),
/// run ([`call`](Vm::call)), and queried ([`read`](Vm::read), [`reveal`](Vm::reveal)).
///
/// The type parameter `T` is the correlated-randomness channel shared with the
/// verifier.
#[derive(Debug)]
pub struct Prover<T> {
    module: Module,
    global: Global,
    svole: T,
    pending_io: PendingIo,
    pending_reveal: RangeSet<u32>,
    reveal_state: host::RevealState,
    auth: AuthState,
    zk: mpz_zk_core::Prover,
    chunk_cap: Option<usize>,
}

impl<T> Prover<T> {
    /// Creates a new prover for `module`, drawing its correlated randomness
    /// from `svole`.
    ///
    /// # Errors
    ///
    /// Returns a [`ZkVmError`] if state for `module` cannot be initialized.
    pub fn new(module: Module, svole: T) -> Result<Self, ZkVmError> {
        let global = Global::new(&module)?;
        let zk = mpz_zk_core::Prover::new();
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
    /// updated prover.
    ///
    /// A value of `Some(cap)` bounds each chunk to at most `cap` operations,
    /// trading proof granularity against memory use. `None` places no bound and
    /// lets a chunk run until the program completes or traps.
    pub fn with_chunk_cap(mut self, cap: Option<usize>) -> Self {
        self.chunk_cap = cap;
        self
    }
}

impl<T> Prover<T>
where
    T: RCOTReceiver<bool, Block> + Flush,
{
    #[tracing::instrument(level = "debug", skip(self, io))]
    async fn allocate(
        &mut self,
        io: &mut Context,
        total: usize,
    ) -> Result<(Vec<bool>, Vec<Gf2_128>), ZkVmError> {
        self.svole
            .alloc(total)
            .map_err(|e| ZkVmError::SvoleAlloc(e.to_string()))?;
        self.svole
            .flush(io)
            .await
            .map_err(|e| ZkVmError::SvoleFlush(e.to_string()))?;
        let RCOTReceiverOutput {
            choices: masks,
            msgs,
            ..
        } = self
            .svole
            .try_recv_rcot(total)
            .map_err(|e| ZkVmError::SvoleIo(e.to_string()))?;
        let macs = msgs.into_iter().map(|m| zerocopy::transmute!(m)).collect();
        Ok((masks, macs))
    }
}

impl<T> Vm for Prover<T>
where
    T: RCOTReceiver<bool, Block> + Flush,
{
    type Error = ZkVmError;

    /// Writes the input `w` to linear memory at byte offset `ptr`.
    ///
    /// A [`Write::Private`] input is committed and contributes to the proof; a
    /// [`Write::Public`] input is visible to both parties and carries no
    /// commitment.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Core`] if the module defines no memory,
    /// [`ZkVmError::Trap`] if the write falls outside the bounds of memory, and
    /// [`ZkVmError::Unsupported`] for a [`Write::Blind`] input, which the prover
    /// cannot supply.
    fn write(&mut self, ptr: u32, w: Write<'_>) -> Result<(), ZkVmError> {
        let memory = self
            .global
            .memory_mut()
            .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
        match w {
            Write::Private(data) => {
                memory.write_bytes(ptr, data).map_err(ZkVmError::Trap)?;
                self.pending_io.write_private(ptr, data.len());
                self.global
                    .set_memory_visibility(ptr, data.len(), Visibility::Private);
            }
            Write::Public(data) => {
                memory.write_bytes(ptr, data).map_err(ZkVmError::Trap)?;
                self.global
                    .set_memory_visibility(ptr, data.len(), Visibility::Public);
            }
            Write::Blind(_) => {
                return Err(ZkVmError::Unsupported(
                    "prover cannot write blind values".into(),
                ));
            }
        }
        Ok(())
    }

    /// Marks the `len` bytes of memory starting at `ptr` to be opened to the
    /// verifier on the next [`call`](Vm::call).
    ///
    /// The cleartext of the range is proven correct before it is revealed, and
    /// the range becomes readable afterwards.
    ///
    /// # Errors
    ///
    /// This method does not currently return an error.
    fn reveal(&mut self, ptr: u32, len: usize) -> Result<(), ZkVmError> {
        self.pending_reveal.union_mut(ptr..ptr + len as u32);
        Ok(())
    }

    /// Returns the `len` bytes of memory starting at `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::Internal`] if the requested range is tainted, that
    /// is, holds a committed value not yet opened via [`reveal`](Vm::reveal),
    /// [`ZkVmError::Core`] if the module defines no memory, and
    /// [`ZkVmError::Trap`] if the range falls outside the bounds of memory.
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

    /// Executes the function `func_idx` with arguments `params`, proving its
    /// execution to the verifier over `io`, and returns its result.
    ///
    /// The prover proves the call correct without revealing its witness,
    /// including the cleartext of any bytes queued by [`reveal`](Vm::reveal).
    /// Pending inputs and reveals are cleared once the call returns.
    ///
    /// Returns `Some(value)` when the function yields a value and `None`
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::InvalidFunction`] if `func_idx` does not name a local
    /// function. Returns a [`ZkVmError`] if proving fails or communication over
    /// `io` fails, and [`ZkVmError::Trap`] if execution is proven to trap.
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
        let mut final_result = None;
        let mut chunk_idx: usize = 0;
        // Memory ranges to open on the first proving chunk. Draining them
        // forces that chunk to prove even if it is otherwise public.
        let reveal_ranges: Vec<Range<u32>> = self.pending_reveal.iter().collect();
        let mut reveal_pending = !reveal_ranges.is_empty();
        // Set once a chunk traps; the proven public outcome.
        let mut trapped: Option<mpz_vm_core::Trap> = None;
        // Set once any chunk performs authenticated work (a commit or proof).
        // A fully public chunk before this point has nothing to prove.
        let mut any_zk_work = false;

        loop {
            let chunk_span = tracing::info_span!("prover.chunk", idx = chunk_idx);
            let _enter = chunk_span.enter();

            // The prover self-discovers traps via `StepResult::Trapped`,
            // so it announces nothing to its own capture.
            let chunk = capture::capture_chunk(
                &self.module,
                &mut self.global,
                &mut thread,
                self.chunk_cap,
                Role::Prover,
                None,
                &mut self.reveal_state,
            )?;
            tracing::debug!(
                events = chunk.trace.len(),
                cost = chunk.cost,
                done = chunk.done,
                "captured chunk"
            );

            // Announce the chunk's trap outcome and disclosed reveals before any
            // allocation, commit, or challenge. `op_counter` is the
            // authoritative global index, identical on both sides for every op
            // up to and including the trap; the reveal payloads let the verifier
            // resolve reveals in lockstep during its own capture.
            let (trap_at, trap) = match &chunk.trap {
                Some(t) => (Some(t.index), Some(t.trap.clone())),
                None => (None, None),
            };
            let outcome = ChunkOutcome {
                trap_at,
                trap,
                revealed: chunk.reveals.clone(),
            };
            io.io_mut()
                .send(outcome)
                .await
                .map_err(|e| ZkVmError::IoSend(e.to_string()))?;

            let execute_bits = commit_bits + chunk.cost;

            // A fully public chunk reached before any authenticated work has
            // nothing to prove: no committed bits, no gates, and any trap it
            // carries is public (no committed divisor). Both sides compute
            // `execute_bits` and the trap shape identically, so they skip the
            // allocate/commit/challenge/proof exchange in lockstep — running it
            // would deadlock on a zero-cost tape. Once a chunk does ZK work the
            // output may be authenticated, so every later chunk must run the
            // exchange to carry the binding forward.
            let needs_zk = execute_bits > 0
                || any_zk_work
                || reveal_pending
                || chunk.trap.as_ref().is_some_and(|t| t.directive.is_some());
            if !needs_zk {
                commit_bits = 0;
                if chunk.done {
                    final_result = chunk.result;
                }
                chunk_idx += 1;
                if let Some(t) = chunk.trap {
                    trapped = Some(t.trap);
                    break;
                }
                if chunk.done {
                    break;
                }
                continue;
            }
            any_zk_work = true;

            let total = execute_bits + VOPE_BITS;
            tracing::info!(commit_bits, cost = chunk.cost, total, "cost plan");

            let (mut masks, macs) = self.allocate(io, total).await?;
            let (exec_masks, vope_masks) = masks.split_at_mut(execute_bits);
            let vope_masks: &[bool; VOPE_BITS] = (&*vope_masks)
                .try_into()
                .expect("vope tail is VOPE_BITS wide");
            let (exec_macs, vope_macs) = macs.split_at(execute_bits);
            let vope_macs: &[Gf2_128; VOPE_BITS] =
                vope_macs.try_into().expect("vope tail is VOPE_BITS wide");

            // Cleartext of bytes opened on this chunk, streamed in the proof.
            let mut revealed: Vec<u8> = Vec::new();
            {
                let mut exec = self
                    .zk
                    .execute(exec_masks, exec_macs)
                    .map_err(|e| ZkVmError::Internal(e.to_string()))?;
                if commit_bits > 0 {
                    commit::commit_prover(
                        &mut self.auth,
                        root_reg_base,
                        &params,
                        &self.pending_io,
                        &self.global,
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
                    // A trapping chunk produces no output to bind. When the
                    // trap is tied to a committed op, prove its divisor is
                    // zero; a fully public trap has no committed divisor.
                    Some(t) => {
                        if let Some(directive) = &t.directive {
                            replay::replay_trap(directive, &t.trap, &self.auth, &mut exec)?;
                        }
                    }
                    None => {
                        // Only a symbolic return is revealed/bound; a concrete
                        // return is already public to both parties.
                        if chunk.result_symbolic {
                            finalize::bind_output(&state, &mut exec, &self.auth, chunk.result)?;
                        }
                    }
                }
                // Open any pending reveals against their committed wires,
                // collecting the cleartext to stream in the proof message.
                if reveal_pending {
                    let memory = self
                        .global
                        .memory()
                        .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
                    revealed =
                        reveal::reveal_prover(&mut exec, &self.auth, memory, &reveal_ranges)?;
                }
                exec.finish()
                    .map_err(|e| ZkVmError::Internal(e.to_string()))?;
            }
            commit_bits = 0;
            // The whole execute tape's adjust witness (commit + gate)
            // ships in one Commit message, sent before the prover learns
            // the verifier's challenge.
            let commit_payload = Commit {
                adjust: exec_masks.iter().copied().collect(),
            };
            io.io_mut()
                .send(commit_payload)
                .await
                .map_err(|e| ZkVmError::IoSend(e.to_string()))?;

            // The verifier samples its challenge only after holding the
            // commitment, so the prover cannot tailor its witness to it.
            let chi: [u8; 32] = io
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;

            if chunk.done {
                final_result = chunk.result;
            }
            // Only a *symbolic* return value is revealed over the wire; a
            // concrete return is already public, so the verifier reconstructs
            // it from its own local result.
            let out_val = if chunk.result_symbolic {
                chunk.result
            } else {
                None
            };
            let proof = self.zk.prove(chi, vope_masks, vope_macs);
            io.io_mut()
                .send(ProofMessage {
                    output: out_val,
                    revealed,
                    proof,
                })
                .await
                .map_err(|e| ZkVmError::IoSend(e.to_string()))?;

            // The opened ranges are now concrete to both parties: drop their
            // taint so subsequent reads succeed. The cleartext already lives in
            // the prover's linear memory (written when it was first stored).
            if reveal_pending {
                for r in &reveal_ranges {
                    self.global.set_memory_visibility(
                        r.start,
                        (r.end - r.start) as usize,
                        Visibility::Public,
                    );
                }
                reveal_pending = false;
            }

            chunk_idx += 1;
            if let Some(t) = chunk.trap {
                trapped = Some(t.trap);
                break;
            }
            if chunk.done {
                break;
            }
        }

        self.pending_io.clear();
        self.pending_reveal = RangeSet::default();
        if let Some(trap) = trapped {
            tracing::info!(chunks = chunk_idx, ?trap, "prover call trapped");
            return Err(ZkVmError::Trap(trap));
        }
        tracing::info!(chunks = chunk_idx, ?final_result, "prover call complete");
        Ok(final_result)
    }
}
