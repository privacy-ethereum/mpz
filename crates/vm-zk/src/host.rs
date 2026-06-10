//! Servicing of guest VCI reveal host calls during capture.
//!
//! When the thread blocks on a `vc::reveal_*` import, [`service_reveal`]
//! records a [`RevealEvent`] into the captured trace and returns the value to
//! resolve the call with. The event is opened in-order during replay against
//! the live authenticated state, so a scalar's source register still holds its
//! MAC at the reveal point (the free-list cannot have recycled it yet).
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
pub(crate) enum RevealEvent {
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
) -> Result<(RevealEvent, Option<Value>, Visibility)> {
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
            let event = RevealEvent::OpenScalar {
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
                RevealEvent::WaitScalar { dst, value },
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
            let event = RevealEvent::OpenBytes {
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
            Ok((RevealEvent::WaitBytes, None, Visibility::Public))
        }
        other => Err(ZkVmError::Unsupported(format!(
            "zk-vm does not service reveal import `vc::{other}`"
        ))),
    }
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
