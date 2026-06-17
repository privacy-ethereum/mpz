use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_fields::gf2_128::Gf2_128;
use mpz_ot_core::rcot::{RCOTSender, RCOTSenderOutput};
use mpz_vm_core::{
    Call, Error as CoreError, Global, Param, Reg, Thread, Visibility, Vm, Write, value::Value,
};
use mpz_vm_ir::{Function, Module};
use rand::Rng;
use rand_chacha::ChaCha12Rng;
use rand_chacha::rand_core::SeedableRng;
use rangeset::set::RangeSet;
use rayon::prelude::*;
use serio::{SinkExt, stream::IoStreamExt};
use std::ops::Range;

use mpz_vm_memory::{AuthState, Bit, Registers};
use mpz_zk_core::{Commitment, MAC_ONE, MAC_ZERO, verifier_wire, vope_sender};

use crate::{
    ChunkOutcome, DEFAULT_CHUNK_CAP, ProofMessage, VOPE_BITS,
    capture::{self, ChunkCapture, Role},
    commit::{self, PendingIo, VerifierTape, prepare_params},
    error::ZkVmError,
    finalize, host,
    replay::{self, ReplayState},
    reveal, segment,
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
    delta: Gf2_128,
    chunk_cap: Option<usize>,
    segment_cost: Option<usize>,
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
            return Err(ZkVmError::DeltaLsb);
        }
        let auth = AuthState::new(Bit(MAC_ZERO), Bit(MAC_ONE + delta));
        Ok(Self {
            module,
            global,
            svole,
            pending_io: PendingIo::default(),
            pending_reveal: RangeSet::default(),
            reveal_state: host::RevealState::default(),
            auth,
            delta,
            chunk_cap: Some(DEFAULT_CHUNK_CAP),
            segment_cost: None,
        })
    }

    /// Sets the maximum number of operations executed per chunk, returning the
    /// updated verifier.
    ///
    /// A value of `Some(cap)` bounds each chunk to at most `cap` operations,
    /// trading proof granularity against memory use; `None` places no bound.
    /// Defaults to [`Some(DEFAULT_CHUNK_CAP)`](crate::DEFAULT_CHUNK_CAP). This
    /// must match the prover's setting for the two sides to agree.
    pub fn with_chunk_cap(mut self, cap: Option<usize>) -> Self {
        self.chunk_cap = cap;
        self
    }

    /// Sets the gate-cost target per proving segment, returning the updated
    /// verifier.
    ///
    /// Splits each chunk into segments folded by parallel workers; see
    /// [`Prover::with_segment_cost`](crate::Prover::with_segment_cost). This
    /// must match the prover's setting for the two sides to agree.
    pub fn with_segment_cost(mut self, cost: Option<usize>) -> Self {
        self.segment_cost = cost;
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

    /// The parallel per-segment accumulate pass: checks the prover's
    /// commitment by folding every segment with the sampled challenge.
    /// Returns the combined `(w, assertions)` and the chunk-final state.
    #[allow(clippy::too_many_arguments)]
    fn accumulate_pass(
        &self,
        chunk: &ChunkCapture,
        plan: &segment::Plan,
        seg_keys: &[Gf2_128],
        seg_adjust: &[bool],
        chi: [u8; 32],
        output: Option<Value>,
        revealed: &[u8],
        reveal_ranges: &[Range<u32>],
        reveal_pending: bool,
    ) -> Result<VAccOut, ZkVmError> {
        let delta = self.delta;
        // Boundary commitment wires, materialized straight off the tape.
        let boundary_wires: Vec<Option<Vec<Gf2_128>>> = plan
            .segments
            .iter()
            .map(|seg| {
                seg.boundary.as_ref().map(|b| {
                    b.tape
                        .clone()
                        .map(|i| verifier_wire(seg_keys[i], seg_adjust[i], delta))
                        .collect()
                })
            })
            .collect();

        let module = &self.module;
        let auth_base = &self.auth;
        let last = plan.segments.len() - 1;
        let pub_bit = move |b: bool| if b { MAC_ONE + delta } else { MAC_ZERO };

        let results: Vec<(Gf2_128, [u8; 32], Option<AuthState>)> = plan
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
                    segment::apply_boundary(&mut auth, prev, wires, &pub_bit)?;
                }

                let mut rng = ChaCha12Rng::from_seed(chi);
                rng.set_word_pos((seg.chi_gates as u128) * 4);
                let mut ctx = mpz_zk_core::Verifier::new(
                    delta,
                    &seg_keys[seg.tape.clone()],
                    &seg_adjust[seg.tape.clone()],
                )
                .map_err(|e| ZkVmError::Internal(e.to_string()))?
                .accumulate(rng);
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
                    segment::assert_boundary(&auth, b, wires, &mut ctx)?;
                }

                let mut last_auth = None;
                if j == last {
                    match &chunk.trap {
                        // A trapping chunk carries no output to authenticate.
                        // When the trap is tied to a committed op, check its
                        // divisor is zero; a fully public trap has no
                        // committed divisor.
                        Some(t) => {
                            if let Some(directive) = &t.directive {
                                replay::replay_trap(directive, &t.trap, &auth, &mut ctx)?;
                            }
                        }
                        None => {
                            // Only a symbolic return is revealed/authenticated;
                            // a concrete return is already public.
                            if chunk.result_symbolic {
                                finalize::bind_output(&state, &mut ctx, &auth, output)?;
                            }
                        }
                    }
                    if reveal_pending {
                        reveal::reveal_verifier(&mut ctx, &auth, reveal_ranges, revealed)?;
                    }
                    last_auth = Some(auth);
                }

                let (w, assertions) = ctx
                    .finish()
                    .map_err(|e| ZkVmError::Internal(e.to_string()))?;
                Ok((w, assertions, last_auth))
            })
            .collect::<Result<_, _>>()?;

        let mut w = Gf2_128::new(0);
        let mut hasher = blake3::Hasher::new();
        let mut final_auth = None;
        for (w_j, h_j, last_auth) in results {
            w = w + w_j;
            hasher.update(&h_j);
            if let Some(auth) = last_auth {
                final_auth = Some(auth);
            }
        }

        Ok(VAccOut {
            w,
            assertions: *hasher.finalize().as_bytes(),
            auth: final_auth.expect("last segment produces final state"),
        })
    }
}

/// Output of the verifier's accumulate pass over one chunk.
struct VAccOut {
    w: Gf2_128,
    assertions: [u8; 32],
    auth: AuthState,
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
                ));
            }
            // Merge the announced reveal payloads before capture so the verifier
            // can resolve this chunk's reveals (and any later wait) in lockstep.
            self.reveal_state.merge(outcome.revealed.clone());

            let chunk = capture::capture_chunk(
                &self.module,
                &mut self.global,
                &mut thread,
                capture::Limits {
                    chunk_cap: self.chunk_cap,
                    segment_cost: self.segment_cost,
                },
                Role::Verifier,
                outcome.trap_at.zip(outcome.trap.clone()),
                &mut self.reveal_state,
            )?;
            tracing::debug!(
                events = chunk.trace.len(),
                cost = chunk.cost,
                done = chunk.done,
                segments = chunk.marks.len() + 1,
                "captured chunk"
            );

            let plan = segment::plan(&chunk, &self.module, &self.auth, &params, root_reg_base);
            let execute_bits = commit_bits + plan.tape_len;

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
                        ));
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
            tracing::info!(
                commit_bits,
                cost = chunk.cost,
                total,
                segments = plan.segments.len(),
                "cost plan"
            );

            let keys = self.allocate(io, total).await?;
            let (exec_keys, vope_keys) = keys.split_at(execute_bits);
            let vope_keys: &[Gf2_128; VOPE_BITS] =
                vope_keys.try_into().expect("vope tail is VOPE_BITS wide");

            // Receive the prover's commitment to the whole execute tape
            // (commit prefix, gates, and boundary commitments), then sample
            // and send the challenge.
            let commitment: Commitment = io
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;
            let adjust: Vec<bool> = commitment.adjust.iter().by_vals().collect();
            if adjust.len() != execute_bits {
                return Err(ZkVmError::Internal(format!(
                    "commit adjust short: got {} want {}",
                    adjust.len(),
                    execute_bits
                )));
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

            // Input-commit prefix: pure tape materialization into the
            // persistent auth state shared by every segment worker.
            if commit_bits > 0 {
                let mut tape = VerifierTape {
                    keys: &exec_keys[..commit_bits],
                    adjust: &adjust[..commit_bits],
                    delta: self.delta,
                    cursor: 0,
                };
                commit::commit_verifier(
                    &mut self.auth,
                    root_reg_base,
                    &params,
                    &self.pending_io,
                    &mut tape,
                )?;
            }

            // ---- Accumulate pass: parallel proof checking ----
            let seg_keys = &exec_keys[commit_bits..];
            let seg_adjust = &adjust[commit_bits..];
            let out = self.accumulate_pass(
                &chunk,
                &plan,
                seg_keys,
                seg_adjust,
                chi,
                output,
                &revealed,
                &reveal_ranges,
                reveal_pending,
            )?;
            // The chunk-final worker state carries every wire forward.
            self.auth = out.auth;
            commit_bits = 0;

            if out.assertions != proof.assertions {
                return Err(ZkVmError::BatchCheckFailed);
            }
            let b = vope_sender(vope_keys);
            if out.w + b != proof.u + self.delta * proof.v {
                return Err(ZkVmError::BatchCheckFailed);
            }

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
                    ));
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

    /// Commits any queued blind writes and checks any queued reveals over `io`
    /// without running a function.
    ///
    /// This mirrors the prover's [`commit`](crate::Prover::commit): a single
    /// proving round commits the wires of every pending [`Write::Blind`] region
    /// and verifies the prover's opening of every pending
    /// [`reveal`](Vm::reveal) range, leaving nothing queued. The committed
    /// memory wires persist and are consumed by a later [`call`](Vm::call).
    ///
    /// # Errors
    ///
    /// Returns a [`ZkVmError`] if verification fails or communication over `io`
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
        let keys = self.allocate(io, total).await?;
        let (exec_keys, vope_keys) = keys.split_at(execute_bits);
        let vope_keys: &[Gf2_128; VOPE_BITS] =
            vope_keys.try_into().expect("vope tail is VOPE_BITS wide");

        let commitment: Commitment = io
            .io_mut()
            .expect_next()
            .await
            .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;
        let adjust: Vec<bool> = commitment.adjust.iter().by_vals().collect();
        if adjust.len() != execute_bits {
            return Err(ZkVmError::Internal(format!(
                "commit adjust short: got {} want {}",
                adjust.len(),
                execute_bits
            )));
        }
        let chi: [u8; 32] = rand::rng().random();
        io.io_mut()
            .send(chi)
            .await
            .map_err(|e| ZkVmError::IoSend(e.to_string()))?;

        let ProofMessage {
            output: _,
            revealed,
            proof,
        } = io
            .io_mut()
            .expect_next()
            .await
            .map_err(|e| ZkVmError::IoRecv(e.to_string()))?;

        if commit_bits > 0 {
            let mut tape = VerifierTape {
                keys: exec_keys,
                adjust: &adjust,
                delta: self.delta,
                cursor: 0,
            };
            commit::commit_memory_verifier(&mut self.auth, &self.pending_io, &mut tape);
        }

        // The commit round folds no gates; a tape-free accumulate context
        // hashes the reveal assertions, mirroring the prover.
        let mut ctx = mpz_zk_core::Verifier::new(self.delta, &[], &[])
            .map_err(|e| ZkVmError::Internal(e.to_string()))?
            .accumulate(ChaCha12Rng::from_seed(chi));
        if reveal_pending {
            reveal::reveal_verifier(&mut ctx, &self.auth, &reveal_ranges, &revealed)?;
        }
        let (w, assertions) = ctx
            .finish()
            .map_err(|e| ZkVmError::Internal(e.to_string()))?;

        if assertions != proof.assertions {
            return Err(ZkVmError::BatchCheckFailed);
        }
        let b = vope_sender(vope_keys);
        if w + b != proof.u + self.delta * proof.v {
            return Err(ZkVmError::BatchCheckFailed);
        }

        // The opening verified: write the revealed cleartext into linear memory
        // and drop the ranges' taint so later reads succeed.
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
        }
        self.pending_io.clear();
        self.pending_reveal = RangeSet::default();
        Ok(())
    }

    /// Runs `func_idx` with `params` using only local work, without an `io`
    /// context.
    ///
    /// Public computation is reproduced in-thread, so a function with public
    /// inputs yields the same value the prover computes, with no communication.
    /// Any authenticated work reports [`ZkVmError::RequiresCommunication`].
    ///
    /// # Errors
    ///
    /// Returns [`ZkVmError::RequiresCommunication`] if `params` carry private
    /// or blind values, if inputs or reveals remain queued (commit them
    /// first), or if execution reaches authenticated work. Otherwise
    /// returns [`ZkVmError::InvalidFunction`] for a bad `func_idx` or
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
