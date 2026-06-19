//! Servicing of guest host calls during capture: `vc::reveal_*` disclosures and
//! the `crypto::*` circuit precompiles.
//!
//! When the thread blocks on such an import, the servicer records a
//! [`HostCallEvent`] into the captured trace and returns the value to resolve
//! the call with. The event is applied in-order during replay against the live
//! authenticated state, so a reveal's source register still holds its MAC at
//! the reveal point (the free-list cannot have recycled it yet).
//!
//! Disclosure is eager: a `reveal_*` call commits its value to the chunk's
//! announced payloads immediately, keyed by a unique reveal id; the matching
//! `*_wait` only retrieves it. The id is allocated from a counter that advances
//! identically on both parties (lockstep capture), so the handle the guest
//! holds is the verifier's lookup key.

use std::collections::BTreeMap;

use mpz_vm_core::{Error as CoreError, Global, Operand, Reg, Visibility, value::Value};
use mpz_vm_ir::{Function, Module};
use serde::{Deserialize, Serialize};

use crate::{
    capture::Role,
    error::{Result, ZkVmError},
};

/// A disclosed reveal, announced in the chunk message keyed by reveal id and
/// asserted against committed wires during replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum RevealPayload {
    /// A scalar value.
    Scalar(Value),
    /// A linear-memory range and its disclosed bytes.
    Bytes { ptr: u32, len: u32, bytes: Vec<u8> },
}

/// A serviced reveal host call, recorded in the trace so replay opens it
/// in-order against the live authenticated state.
#[derive(Clone, Debug)]
pub(crate) enum HostCallEvent {
    /// `vc::reveal_<ty>(value) -> handle`: open `src`'s MAC against `value`
    /// (skipped when the value was already public, i.e. `src` is `None`), and
    /// bind the public handle `id` into `handle_dst`.
    OpenScalar {
        src: Option<Reg>,
        value: Value,
        handle_dst: Reg,
        id: u32,
    },
    /// `vc::reveal_<ty>_wait(handle) -> value`: bind the now-public revealed
    /// value into `dst`.
    WaitScalar { dst: Reg, value: Value },
    /// `vc::reveal_bytes(ptr, len) -> handle`: open the range's byte MACs
    /// against `bytes`, and bind the public handle `id` into `handle_dst`.
    OpenBytes {
        ptr: u32,
        bytes: Vec<u8>,
        handle_dst: Reg,
        id: u32,
    },
    /// `vc::reveal_bytes_wait(handle)`: its effect (making the range public and
    /// materializing the bytes) is applied to memory during capture, so replay
    /// has nothing to do. Recorded to stay 1:1 with the import directives.
    WaitBytes,
    /// `crypto::sha256_compress(state_ptr, block_ptr)` with at least one
    /// tainted input byte: replay emits the SHA-256 compression circuit over
    /// the input wires and writes the committed output back over the
    /// 32-byte state at `state_ptr`. Inputs may mix committed and public
    /// bytes (e.g. a public IV / SHA padding), so each region carries its
    /// public bytes (symbolic positions zeroed) and a per-byte symbolic
    /// mask, mirroring `Op::Load`'s `concrete`/`symbolic_mask`: replay
    /// reads symbolic bytes from committed memory and materializes public
    /// bytes as public-bit wires.
    Sha256Compress {
        state_ptr: u32,
        block_ptr: u32,
        state_pub: [u8; 32],
        state_sym: u64,
        block_pub: [u8; 64],
        block_sym: u64,
    },
    /// `crypto::sha256_compress` over fully public input: the digest is
    /// computed in the clear during capture; replay writes it back as
    /// public-bit wires (no gates). `digest` holds the 32-byte result.
    Sha256CompressPublic { state_ptr: u32, digest: [u8; 32] },
}

/// Per-execution reveal state, owned by the prover/verifier across chunks.
#[derive(Debug, Default)]
pub(crate) struct RevealState {
    /// Monotonic reveal-id counter; identical on both parties (lockstep
    /// capture).
    next_id: u32,
    /// Every payload disclosed so far, keyed by reveal id. The prover fills
    /// this as it services reveals; the verifier merges each chunk's
    /// announced payloads before capturing it.
    payloads: BTreeMap<u32, RevealPayload>,
}

impl RevealState {
    /// Merges a chunk's announced payloads (verifier side, before capture).
    pub(crate) fn merge(&mut self, announced: BTreeMap<u32, RevealPayload>) {
        self.payloads.extend(announced);
    }

    /// Allocates the next reveal id.
    fn alloc(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Records a disclosed payload (prover side) both for replay lookups and in
    /// `new` to announce in this chunk's message.
    fn disclose(
        &mut self,
        new: &mut BTreeMap<u32, RevealPayload>,
        id: u32,
        payload: RevealPayload,
    ) {
        self.payloads.insert(id, payload.clone());
        new.insert(id, payload);
    }
}

/// Services a reveal host call surfaced during capture.
///
/// Returns the trace event to record (if any) and the value to resolve the host
/// call with (the handle for a `reveal`, the revealed value for a scalar
/// `wait`, nothing for a byte `wait`). The prover inserts newly disclosed
/// payloads into `new` (to announce) and into its own `payloads`; the verifier
/// reads them from `payloads`, pre-merged from the chunk message. Byte waits
/// apply their effect — making the range public and (verifier) materializing
/// its bytes — to `global` directly and carry no trace event.
#[allow(clippy::too_many_arguments)]
pub(crate) fn service_reveal(
    role: Role,
    state: &mut RevealState,
    new: &mut BTreeMap<u32, RevealPayload>,
    module: &Module,
    global: &mut Global,
    func_idx: u32,
    dst: Option<Reg>,
    args: &[Operand],
) -> Result<(HostCallEvent, Option<Value>, Visibility)> {
    let name = match module.function(func_idx) {
        Some(Function::Import(import)) if import.module() == "vc" => import.name(),
        _ => {
            return Err(ZkVmError::Unsupported(
                "zk-vm services only `vc` reveal imports".into(),
            ));
        }
    };

    match name {
        "reveal_i32" | "reveal_i64" => {
            let id = state.alloc();
            let (src, value) = match args.first() {
                // Already public: nothing to open.
                Some(Operand::Concrete(v)) => (None, *v),
                Some(Operand::Symbol { reg, value }) => {
                    let v = match role {
                        Role::Prover => (*value).ok_or_else(|| {
                            ZkVmError::Internal("prover does not hold revealed value".into())
                        })?,
                        Role::Verifier => scalar(state.payloads.get(&id), id)?,
                    };
                    (Some(*reg), v)
                }
                None => return Err(ZkVmError::Internal("reveal call missing argument".into())),
            };
            if role == Role::Prover {
                state.disclose(new, id, RevealPayload::Scalar(value));
            }
            let handle_dst = handle_dst(dst)?;
            let event = HostCallEvent::OpenScalar {
                src,
                value,
                handle_dst,
                id,
            };
            Ok((event, Some(Value::I32(id as i32)), Visibility::Public))
        }
        "reveal_i64_wait" | "reveal_i32_wait" => {
            let handle = handle_arg(args)?;
            let value = scalar(state.payloads.get(&handle), handle)?;
            let dst =
                dst.ok_or_else(|| ZkVmError::Internal("reveal wait has no destination".into()))?;
            Ok((
                HostCallEvent::WaitScalar { dst, value },
                Some(value),
                Visibility::Public,
            ))
        }
        "reveal_bytes" => {
            let id = state.alloc();
            let ptr = arg_u32(args, 0)?;
            let len = arg_u32(args, 1)?;
            let bytes = match role {
                Role::Prover => global
                    .memory()
                    .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?
                    .read_bytes(ptr, len as usize)
                    .map_err(ZkVmError::Trap)?
                    .to_vec(),
                Role::Verifier => bytes_payload(state.payloads.get(&id), id)?.2,
            };
            if role == Role::Prover {
                state.disclose(
                    new,
                    id,
                    RevealPayload::Bytes {
                        ptr,
                        len,
                        bytes: bytes.clone(),
                    },
                );
            }
            let handle_dst = handle_dst(dst)?;
            let event = HostCallEvent::OpenBytes {
                ptr,
                bytes,
                handle_dst,
                id,
            };
            Ok((event, Some(Value::I32(id as i32)), Visibility::Public))
        }
        "reveal_bytes_wait" => {
            // Eager disclosure already opened the range; the wait makes it public
            // and, on the verifier, materializes the bytes it learned. These are
            // capture-time effects on `global`, so there is no replay event.
            let handle = handle_arg(args)?;
            let (ptr, len, bytes) = bytes_payload(state.payloads.get(&handle), handle)?;
            if role == Role::Verifier {
                global
                    .memory_mut()
                    .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?
                    .write_bytes(ptr, &bytes)
                    .map_err(ZkVmError::Trap)?;
            }
            global.set_memory_visibility(ptr, len as usize, Visibility::Public);
            Ok((HostCallEvent::WaitBytes, None, Visibility::Public))
        }
        other => Err(ZkVmError::Unsupported(format!(
            "zk-vm does not service reveal import `vc::{other}`"
        ))),
    }
}

/// Services a `crypto::sha256_compress(state_ptr, block_ptr)` host call
/// surfaced during capture.
///
/// Both pointers are public concrete operands. The output is committed iff any
/// of the 96 input bytes is tainted — a decision identical on both parties,
/// since taint is identical on both. When all inputs are public, both parties
/// compute the digest in the clear (public fast-path, no circuit). Otherwise
/// the prover computes and writes the digest and marks the 32-byte output
/// `Private`; the verifier only marks it `Blind`, and replay proves the
/// compression circuit on both sides.
pub(crate) fn service_sha256_compress(
    role: Role,
    global: &mut Global,
    args: &[Operand],
) -> Result<(HostCallEvent, Option<Value>, Visibility)> {
    let state_ptr = arg_u32(args, 0)?;
    let block_ptr = arg_u32(args, 1)?;

    // Per-byte taint of each input region (identical on both parties), with the
    // public bytes (symbolic positions zeroed) for replay's public-bit wires.
    let (state_pub, state_sym) = masked_input::<32>(global, state_ptr)?;
    let (block_pub, block_sym) = masked_input::<64>(global, block_ptr)?;

    if state_sym == 0 && block_sym == 0 {
        // Public fast-path: every input byte is public, so both parties hold the
        // full input (the masked bytes are the whole input), compute the digest
        // in the clear, write it back, and keep the output public. No circuit.
        let digest = compress_block(&state_pub, &block_pub);
        write_state(global, state_ptr, &digest)?;
        global.set_memory_visibility(state_ptr, 32, Visibility::Public);
        return Ok((
            HostCallEvent::Sha256CompressPublic { state_ptr, digest },
            None,
            Visibility::Public,
        ));
    }

    // Authenticated path: a tainted input means the whole output is committed.
    match role {
        Role::Prover => {
            let (state, block) = read_inputs(global, state_ptr, block_ptr)?;
            let digest = compress_block(&state, &block);
            write_state(global, state_ptr, &digest)?;
            global.set_memory_visibility(state_ptr, 32, Visibility::Private);
        }
        // The verifier cannot compute the digest; it only marks the output
        // region committed-and-blind so its taint matches the prover's.
        Role::Verifier => global.set_memory_visibility(state_ptr, 32, Visibility::Blind),
    }
    Ok((
        HostCallEvent::Sha256Compress {
            state_ptr,
            block_ptr,
            state_pub,
            state_sym,
            block_pub,
            block_sym,
        },
        None,
        Visibility::Public,
    ))
}

/// Reads the `N`-byte input region at `ptr`, returning its public bytes (with
/// symbolic positions zeroed) and a per-byte symbolic mask (bit `i` set means
/// byte `i` is committed/symbolic). Both parties derive the same result: taint
/// is identical across parties, public bytes match, and symbolic bytes are
/// zeroed (their value comes from the committed wires at replay).
fn masked_input<const N: usize>(global: &Global, ptr: u32) -> Result<([u8; N], u64)> {
    debug_assert!(N <= 64, "symbolic mask is a u64");
    let mem = global
        .memory()
        .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
    let raw = mem.read_bytes(ptr, N).map_err(ZkVmError::Trap)?;
    let mut public = [0u8; N];
    let mut sym = 0u64;
    for (i, slot) in public.iter_mut().enumerate() {
        if global.memory_tainted(ptr + i as u32, 1) {
            sym |= 1u64 << i;
        } else {
            *slot = raw[i];
        }
    }
    Ok((public, sym))
}

/// Reads the 32-byte state and 64-byte block from memory as owned arrays (so a
/// subsequent mutable write-back doesn't alias the read borrow).
fn read_inputs(global: &Global, state_ptr: u32, block_ptr: u32) -> Result<([u8; 32], [u8; 64])> {
    let mem = global
        .memory()
        .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
    let mut state = [0u8; 32];
    state.copy_from_slice(mem.read_bytes(state_ptr, 32).map_err(ZkVmError::Trap)?);
    let mut block = [0u8; 64];
    block.copy_from_slice(mem.read_bytes(block_ptr, 64).map_err(ZkVmError::Trap)?);
    Ok((state, block))
}

/// Writes the 32-byte `digest` back over the state at `state_ptr`.
fn write_state(global: &mut Global, state_ptr: u32, digest: &[u8; 32]) -> Result<()> {
    global
        .memory_mut()
        .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?
        .write_bytes(state_ptr, digest)
        .map_err(ZkVmError::Trap)?;
    Ok(())
}

/// Computes one SHA-256 compression in the clear via the `sha2` crate. The
/// `state` is eight native-endian `u32` words (the precompile's `[u32; 8]`
/// state, little-endian in linear memory); the `block` is 16 big-endian `u32`
/// words, per standard SHA-256. Capture works in the clear; only the
/// witness/replay phase needs the circuit representation.
fn compress_block(state: &[u8; 32], block: &[u8; 64]) -> [u8; 32] {
    let mut h: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes([
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ])
    });
    sha2::compress256(&mut h, &[(*block).into()]);
    let mut digest = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        digest[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

fn scalar(payload: Option<&RevealPayload>, id: u32) -> Result<Value> {
    match payload {
        Some(RevealPayload::Scalar(v)) => Ok(*v),
        _ => Err(ZkVmError::Internal(format!(
            "no scalar reveal payload for id {id}"
        ))),
    }
}

fn bytes_payload(payload: Option<&RevealPayload>, id: u32) -> Result<(u32, u32, Vec<u8>)> {
    match payload {
        Some(RevealPayload::Bytes { ptr, len, bytes }) => Ok((*ptr, *len, bytes.clone())),
        _ => Err(ZkVmError::Internal(format!(
            "no byte reveal payload for id {id}"
        ))),
    }
}

fn handle_dst(dst: Option<Reg>) -> Result<Reg> {
    dst.ok_or_else(|| ZkVmError::Internal("reveal call has no handle destination".into()))
}

fn handle_arg(args: &[Operand]) -> Result<u32> {
    let v = match args.first() {
        Some(Operand::Concrete(v)) | Some(Operand::Symbol { value: Some(v), .. }) => *v,
        _ => {
            return Err(ZkVmError::Internal(
                "reveal wait handle is not available".into(),
            ));
        }
    };
    v.as_i32()
        .map(|h| h as u32)
        .map_err(|_| ZkVmError::Internal("reveal wait handle is not an i32".into()))
}

fn arg_u32(args: &[Operand], i: usize) -> Result<u32> {
    let v = match args.get(i) {
        Some(Operand::Concrete(v)) | Some(Operand::Symbol { value: Some(v), .. }) => *v,
        _ => {
            return Err(ZkVmError::Unsupported(
                "zk-vm: reveal_bytes requires concrete ptr and len".into(),
            ));
        }
    };
    v.as_i32()
        .map(|x| x as u32)
        .map_err(|_| ZkVmError::Internal("reveal_bytes ptr/len is not an i32".into()))
}
