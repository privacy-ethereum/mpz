use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_ot_core::rcot::{RCOTReceiver, RCOTReceiverOutput};
use mpz_vm_core::{
    Call, Error as CoreError, Global, Param, Reg, Thread, Visibility, Vm, Write, value::Value,
};
use mpz_vm_ir::{Function, Module};

use mpz_vm_memory::{AuthState, Bit, Registers};
use mpz_zk_core::{Commitment, MAC_ONE, MAC_ZERO, Proof, prover_wire, vope_receiver};
use rand_chacha::ChaCha12Rng;
use rand_chacha::rand_core::SeedableRng;
use rangeset::set::RangeSet;
use rayon::prelude::*;
use serio::{SinkExt, stream::IoStreamExt};
use std::ops::Range;

use crate::{
    ChunkOutcome, DEFAULT_CHUNK_CAP, ProofMessage, VOPE_BITS,
    capture::{self, ChunkCapture, Role},
    commit::{self, PendingIo, ProverTape, prepare_params},
    error::ZkVmError,
    finalize, host,
    replay::{self, ReplayState},
    reveal, segment,
};

/// A zero-knowledge prover that executes a [`Module`] and proves correct
/// execution to a [`Verifier`](crate::Verifier).
///
/// The prover holds the private witness and produces a proof that the module
/// was executed correctly without revealing that witness. It implements the
/// [`Vm`] trait, through which a program is loaded with inputs
/// ([`write`](Vm::write)), run ([`call`](Vm::call)), and queried
/// ([`read`](Vm::read), [`reveal`](Vm::reveal)).
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
    chunk_cap: Option<usize>,
    segment_cost: Option<usize>,
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
        let auth = AuthState::new(Bit(MAC_ZERO), Bit(MAC_ONE));
        Ok(Self {
            module,
            global,
            svole,
            pending_io: PendingIo::default(),
            pending_reveal: RangeSet::default(),
            reveal_state: host::RevealState::default(),
            auth,
            chunk_cap: Some(DEFAULT_CHUNK_CAP),
            segment_cost: None,
        })
    }

    /// Sets the maximum number of operations executed per chunk, returning the
    /// updated prover.
    ///
    /// A value of `Some(cap)` bounds each chunk to at most `cap` operations,
    /// trading proof granularity against memory use. `None` places no bound and
    /// lets a chunk run until the program completes or traps. Defaults to
    /// [`Some(DEFAULT_CHUNK_CAP)`](crate::DEFAULT_CHUNK_CAP).
    pub fn with_chunk_cap(mut self, cap: Option<usize>) -> Self {
        self.chunk_cap = cap;
        self
    }

    /// Sets the gate-cost target per proving segment, returning the updated
    /// prover.
    ///
    /// A value of `Some(cost)` splits each chunk's trace into segments of
    /// roughly `cost` gate bits, which are committed and folded by parallel
    /// workers and stitched together with boundary commitments. `None` proves
    /// each chunk as a single segment. This must match the verifier's setting
    /// for the two sides to agree.
    pub fn with_segment_cost(mut self, cost: Option<usize>) -> Self {
        self.segment_cost = cost;
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

    /// Runs the two-pass proof of one chunk: the parallel per-segment commit
    /// pass over `exec_masks`, and — once `chi` is known — the parallel
    /// per-segment accumulate pass yielding the combined `(u, v, assertions)`
    /// plus the chunk-final state.
    ///
    /// `commit_bits` is the input-commit prefix length; the segment region
    /// (gates, advice, and boundary commitments) follows it.
    #[allow(clippy::too_many_arguments)]
    fn commit_pass(
        &mut self,
        chunk: &ChunkCapture,
        plan: &segment::Plan,
        commit_bits: usize,
        root_reg_base: Reg,
        params: &[Param],
        exec_masks: &mut [bool],
        exec_macs: &[Gf2_128],
    ) -> Result<Vec<Option<Vec<bool>>>, ZkVmError> {
        // Input-commit prefix: pure tape materialization. Installs the real
        // MAC wires into the persistent auth state, which every segment
        // worker starts from (in both passes — the commit pass only reads
        // their pointer bits).
        let (prefix_masks, seg_masks) = exec_masks.split_at_mut(commit_bits);
        let (prefix_macs, _) = exec_macs.split_at(commit_bits);
        if commit_bits > 0 {
            let mut tape = ProverTape {
                masks: prefix_masks,
                macs: prefix_macs,
                cursor: 0,
            };
            commit::commit_prover(
                &mut self.auth,
                root_reg_base,
                params,
                &self.pending_io,
                &self.global,
                &mut tape,
            )?;
        }

        // Boundary plaintext, resolved from the capture snapshots, and the
        // boundary commitments XORed straight into the mask region.
        let mut boundary_bits: Vec<Option<Vec<bool>>> = Vec::with_capacity(plan.segments.len());
        for seg in &plan.segments {
            match &seg.boundary {
                Some(b) => {
                    let bits = segment::boundary_bits(b)?;
                    for (i, &bit) in bits.iter().enumerate() {
                        seg_masks[b.tape.start + i] ^= bit;
                    }
                    boundary_bits.push(Some(bits));
                }
                None => boundary_bits.push(None),
            }
        }

        // Pointer-bit wires for every delta boundary, shared across workers:
        // worker `j` seeds from all deltas before its segment.
        let ptr_wires: Vec<Option<Vec<Gf2_128>>> = boundary_bits
            .iter()
            .map(|bits| {
                bits.as_ref()
                    .map(|b| b.iter().map(|&bit| Gf2_128::new(bit as u128)).collect())
            })
            .collect();

        // Parallel per-segment commit workers: plaintext circuit evaluation
        // over pointer-bit wires, adjusting each segment's gate/advice masks
        // in place.
        let gate_masks = gate_mask_slices(seg_masks, &plan.segments);
        let module = &self.module;
        let auth_base = &self.auth;
        plan.segments
            .par_iter()
            .zip(gate_masks)
            .enumerate()
            .try_for_each(|(j, (seg, gmasks))| -> Result<(), ZkVmError> {
                let mut auth = auth_base.clone();
                for (prev_seg, prev_wires) in plan.segments.iter().zip(&ptr_wires).take(j) {
                    let prev = prev_seg
                        .boundary
                        .as_ref()
                        .expect("non-final segments carry a boundary");
                    let wires = prev_wires.as_ref().expect("wires for boundary");
                    segment::apply_boundary(&mut auth, prev, wires, &pub_bit_prover)?;
                }
                let mut ctx = mpz_zk_core::Commit::new(gmasks);
                let mut state = ReplayState::root();
                replay::replay(
                    &chunk.trace[seg.directives.clone()],
                    &chunk.reveal_actions[seg.reveals.clone()],
                    module,
                    &mut auth,
                    &mut ctx,
                    &mut state,
                )?;
                ctx.finish()
                    .map_err(|e| ZkVmError::Internal(e.to_string()))?;
                Ok(())
            })?;

        Ok(boundary_bits)
    }

    /// The parallel per-segment accumulate pass. Returns the combined
    /// `(u, v, assertions)`, the opened reveal cleartext, and the chunk-final
    /// authenticated state to persist.
    #[allow(clippy::too_many_arguments)]
    fn accumulate_pass(
        &self,
        chunk: &ChunkCapture,
        plan: &segment::Plan,
        boundary_bits: &[Option<Vec<bool>>],
        seg_macs: &[Gf2_128],
        chi: [u8; 32],
        reveal_ranges: &[Range<u32>],
        reveal_pending: bool,
    ) -> Result<AccOut, ZkVmError> {
        // Boundary commitment wires, materialized straight off the tape.
        let boundary_wires: Vec<Option<Vec<Gf2_128>>> = plan
            .segments
            .iter()
            .zip(boundary_bits)
            .map(|(seg, bits)| {
                seg.boundary.as_ref().map(|b| {
                    let bits = bits.as_ref().expect("bits for boundary");
                    bits.iter()
                        .enumerate()
                        .map(|(i, &bit)| prover_wire(seg_macs[b.tape.start + i], bit))
                        .collect()
                })
            })
            .collect();

        let module = &self.module;
        let auth_base = &self.auth;
        let memory = self.global.memory();
        let last = plan.segments.len() - 1;

        let results: Vec<(Gf2_128, Gf2_128, [u8; 32], Option<LastOut>)> = plan
            .segments
            .par_iter()
            .enumerate()
            .map(|(j, seg)| -> Result<_, ZkVmError> {
                let mut auth = auth_base.clone();
                for (prev_seg, prev_wires) in plan.segments.iter().zip(&boundary_wires).take(j) {
                    let prev = prev_seg
                        .boundary
                        .as_ref()
                        .expect("non-final segments carry a boundary");
                    let wires = prev_wires.as_ref().expect("wires for boundary");
                    segment::apply_boundary(&mut auth, prev, wires, &pub_bit_prover)?;
                }

                let mut rng = ChaCha12Rng::from_seed(chi);
                rng.set_word_pos((seg.chi_gates as u128) * 4);
                let mut ctx =
                    mpz_zk_core::Prover::committed(&seg_macs[seg.tape.clone()]).accumulate(rng);
                let mut state = ReplayState::root();
                replay::replay(
                    &chunk.trace[seg.directives.clone()],
                    &chunk.reveal_actions[seg.reveals.clone()],
                    module,
                    &mut auth,
                    &mut ctx,
                    &mut state,
                )?;

                if let Some(b) = &seg.boundary {
                    let wires = boundary_wires[j].as_ref().expect("wires for boundary");
                    segment::assert_boundary(&auth, b, wires, &mut ctx).map_err(|e| {
                        ZkVmError::Internal(format!(
                            "segment {j} (directives {:?}): {e}",
                            seg.directives
                        ))
                    })?;
                }

                let mut last_out = None;
                if j == last {
                    let mut revealed = Vec::new();
                    match &chunk.trap {
                        // A trapping chunk produces no output to bind. When the
                        // trap is tied to a committed op, prove its divisor is
                        // zero; a fully public trap has no committed divisor.
                        Some(t) => {
                            if let Some(directive) = &t.directive {
                                replay::replay_trap(directive, &t.trap, &auth, &mut ctx)?;
                            }
                        }
                        None => {
                            // Only a symbolic return is revealed/bound; a concrete
                            // return is already public to both parties.
                            if chunk.result_symbolic {
                                finalize::bind_output(&state, &mut ctx, &auth, chunk.result)?;
                            }
                        }
                    }
                    if reveal_pending {
                        let memory = memory.ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
                        revealed = reveal::reveal_prover(&mut ctx, &auth, memory, reveal_ranges)?;
                    }
                    last_out = Some(LastOut { auth, revealed });
                }

                let (u, v, assertions) = ctx
                    .finish()
                    .map_err(|e| ZkVmError::Internal(e.to_string()))?;
                Ok((u, v, assertions, last_out))
            })
            .collect::<Result<_, _>>()?;

        let mut u = Gf2_128::new(0);
        let mut v = Gf2_128::new(0);
        let mut hasher = blake3::Hasher::new();
        let mut final_out = None;
        for (u_j, v_j, h_j, last_out) in results {
            u = u + u_j;
            v = v + v_j;
            hasher.update(&h_j);
            if let Some(out) = last_out {
                final_out = Some(out);
            }
        }
        let LastOut { auth, revealed } = final_out.expect("last segment produces final state");

        Ok(AccOut {
            u,
            v,
            assertions: *hasher.finalize().as_bytes(),
            revealed,
            auth,
        })
    }
}

/// Output of the prover's accumulate pass over one chunk.
struct AccOut {
    u: Gf2_128,
    v: Gf2_128,
    assertions: [u8; 32],
    revealed: Vec<u8>,
    auth: AuthState,
}

struct LastOut {
    auth: AuthState,
    revealed: Vec<u8>,
}

/// The prover's wire for a public bit.
fn pub_bit_prover(bit: bool) -> Gf2_128 {
    if bit { MAC_ONE } else { MAC_ZERO }
}

/// Splits the segment mask region into per-segment gate/advice slices,
/// skipping the (already finalized) boundary blocks between them.
fn gate_mask_slices<'m>(
    mut region: &'m mut [bool],
    segments: &[segment::Segment],
) -> Vec<&'m mut [bool]> {
    let mut out = Vec::with_capacity(segments.len());
    for seg in segments {
        let (gates, rest) = region.split_at_mut(seg.tape.len());
        out.push(gates);
        region = match &seg.boundary {
            Some(b) => rest.split_at_mut(b.tape.len()).1,
            None => rest,
        };
    }
    out
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
    /// [`ZkVmError::Unsupported`] for a [`Write::Blind`] input, which the
    /// prover cannot supply.
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
    /// Returns [`ZkVmError::InvalidFunction`] if `func_idx` does not name a
    /// local function. Returns a [`ZkVmError`] if proving fails or
    /// communication over `io` fails, and [`ZkVmError::Trap`] if execution
    /// is proven to trap.
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
                capture::Limits {
                    chunk_cap: self.chunk_cap,
                    segment_cost: self.segment_cost,
                },
                Role::Prover,
                None,
                &mut self.reveal_state,
            )?;
            tracing::debug!(
                events = chunk.trace.len(),
                cost = chunk.cost,
                done = chunk.done,
                segments = chunk.marks.len() + 1,
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

            let plan = segment::plan(&chunk, &self.module, &self.auth, &params, root_reg_base);
            let execute_bits = commit_bits + plan.tape_len;

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
            tracing::info!(
                commit_bits,
                cost = chunk.cost,
                total,
                segments = plan.segments.len(),
                "cost plan"
            );

            let (mut masks, macs) = self.allocate(io, total).await?;
            let (exec_masks, vope_masks) = masks.split_at_mut(execute_bits);
            let vope_masks: &[bool; VOPE_BITS] = (&*vope_masks)
                .try_into()
                .expect("vope tail is VOPE_BITS wide");
            let (exec_macs, vope_macs) = macs.split_at(execute_bits);
            let vope_macs: &[Gf2_128; VOPE_BITS] =
                vope_macs.try_into().expect("vope tail is VOPE_BITS wide");

            // ---- Commit pass: parallel plaintext evaluation ----
            let boundary_bits = self.commit_pass(
                &chunk,
                &plan,
                commit_bits,
                root_reg_base,
                &params,
                exec_masks,
                exec_macs,
            )?;
            commit_bits = 0;

            // The whole execute tape's adjust witness (commit prefix, gates,
            // and boundary commitments) ships in one Commitment message, sent
            // before the prover learns the verifier's challenge.
            let commitment = Commitment {
                adjust: exec_masks.iter().copied().collect(),
            };
            io.io_mut()
                .send(commitment)
                .await
                .map_err(|e| ZkVmError::IoSend(e.to_string()))?;

            // The verifier samples its challenge only after holding the
            // commitment, so the prover cannot tailor its witness to it.
            let chi: [u8; 32] = io
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;

            // ---- Accumulate pass: parallel proof folding ----
            let seg_macs = &exec_macs[exec_macs.len() - plan.tape_len..];
            let out = self.accumulate_pass(
                &chunk,
                &plan,
                &boundary_bits,
                seg_macs,
                chi,
                &reveal_ranges,
                reveal_pending,
            )?;
            // The chunk-final worker state carries every wire forward.
            self.auth = out.auth;

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
            let (a_0, a_1) = vope_receiver(vope_masks, vope_macs);
            let proof = Proof {
                assertions: out.assertions,
                u: out.u + a_0,
                v: out.v + a_1,
            };
            io.io_mut()
                .send(ProofMessage {
                    output: out_val,
                    revealed: out.revealed,
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

    /// Commits any queued private writes and opens any queued reveals over `io`
    /// without running a function.
    ///
    /// This performs a single proving round that commits the wires of every
    /// pending [`Write::Private`] region and proves-then-opens every pending
    /// [`reveal`](Vm::reveal) range, leaving nothing queued. The committed
    /// memory wires persist and are consumed by a later [`call`](Vm::call).
    ///
    /// # Errors
    ///
    /// Returns a [`ZkVmError`] if proving fails or communication over `io`
    /// fails.
    #[tracing::instrument(level = "info", skip(self, io))]
    async fn commit(&mut self, io: &mut Context) -> Result<(), ZkVmError> {
        let commit_bits = self.pending_io.cost_bits();
        let reveal_ranges: Vec<Range<u32>> = self.pending_reveal.iter().collect();
        let reveal_pending = !reveal_ranges.is_empty();
        if commit_bits == 0 && !reveal_pending {
            return Ok(());
        }

        // A commit round runs no gates, so the only authenticated bits are the
        // committed inputs.
        let execute_bits = commit_bits;
        let total = execute_bits + VOPE_BITS;
        let (mut masks, macs) = self.allocate(io, total).await?;
        let (exec_masks, vope_masks) = masks.split_at_mut(execute_bits);
        let vope_masks: &[bool; VOPE_BITS] = (&*vope_masks)
            .try_into()
            .expect("vope tail is VOPE_BITS wide");
        let (exec_macs, vope_macs) = macs.split_at(execute_bits);
        let vope_macs: &[Gf2_128; VOPE_BITS] =
            vope_macs.try_into().expect("vope tail is VOPE_BITS wide");

        if commit_bits > 0 {
            let mut tape = ProverTape {
                masks: exec_masks,
                macs: exec_macs,
                cursor: 0,
            };
            commit::commit_memory_prover(
                &mut self.auth,
                &self.pending_io,
                &self.global,
                &mut tape,
            )?;
        }

        let commitment = Commitment {
            adjust: exec_masks.iter().copied().collect(),
        };
        io.io_mut()
            .send(commitment)
            .await
            .map_err(|e| ZkVmError::IoSend(e.to_string()))?;
        let chi: [u8; 32] = io
            .io_mut()
            .expect_next()
            .await
            .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;

        // The commit round folds no gates; a tape-free accumulate context
        // hashes the reveal assertions into the proof.
        let mut revealed: Vec<u8> = Vec::new();
        let mut ctx = mpz_zk_core::Prover::committed(&[]).accumulate(ChaCha12Rng::from_seed(chi));
        if reveal_pending {
            let memory = self
                .global
                .memory()
                .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
            revealed = reveal::reveal_prover(&mut ctx, &self.auth, memory, &reveal_ranges)?;
        }
        let (u, v, assertions) = ctx
            .finish()
            .map_err(|e| ZkVmError::Internal(e.to_string()))?;

        let (a_0, a_1) = vope_receiver(vope_masks, vope_macs);
        let proof = Proof {
            assertions,
            u: u + a_0,
            v: v + a_1,
        };
        io.io_mut()
            .send(ProofMessage {
                output: None,
                revealed,
                proof,
            })
            .await
            .map_err(|e| ZkVmError::IoSend(e.to_string()))?;

        // Opened ranges are now public to both parties; drop their taint so
        // later reads succeed. The cleartext already lives in linear memory.
        if reveal_pending {
            for r in &reveal_ranges {
                self.global.set_memory_visibility(
                    r.start,
                    (r.end - r.start) as usize,
                    Visibility::Public,
                );
            }
        }
        self.pending_io.clear();
        self.pending_reveal = RangeSet::default();
        Ok(())
    }

    /// Runs `func_idx` with `params` using only local work, without an `io`
    /// context.
    ///
    /// Public computation is reproduced in-thread, so a function with public
    /// inputs runs with no communication. Any authenticated work — a symbolic
    /// op, a private branch, or a reveal host call — reports
    /// [`ZkVmError::RequiresCommunication`].
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::RequiresCommunication`] if `params` carry private
    /// or blind values, if inputs or reveals remain queued (commit them first),
    /// or if execution reaches authenticated work. Otherwise returns
    /// [`ZkVmError::InvalidFunction`] for a bad `func_idx` or
    /// [`ZkVmError::Trap`] on a trap.
    fn call_local(
        &mut self,
        func_idx: u32,
        params: Vec<Param>,
    ) -> Result<Option<Value>, ZkVmError> {
        match self.module.function(func_idx) {
            Some(Function::Local(_)) => {}
            _ => return Err(ZkVmError::Core(CoreError::InvalidFunction(func_idx))),
        }
        if prepare_params(&params)? > 0 {
            return Err(ZkVmError::RequiresCommunication(
                "call_local requires public params; private or blind inputs need a proving round"
                    .into(),
            ));
        }
        if self.pending_io.cost_bits() > 0 || !self.pending_reveal.is_empty() {
            return Err(ZkVmError::RequiresCommunication(
                "queued inputs or reveals must be flushed with commit before call_local".into(),
            ));
        }

        let mut thread = Thread::new();
        thread.call(&self.module, &mut self.global, Call { func_idx, params })?;
        capture::run_local(&self.module, &mut self.global, &mut thread)
    }
}
