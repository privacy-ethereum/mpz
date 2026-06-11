use mpz_fields::gf2_128::Gf2_128;
use mpz_vm_core::{Error as CoreError, Global, Param, Reg, value::Value};
use rangeset::set::RangeSet;
use std::ops::Range;

use mpz_vm_memory::{AuthState, AuthValue, Bit, Byte};

use crate::error::{Result, ZkVmError};

#[derive(Debug, Default)]
pub(crate) struct PendingIo {
    write_private: RangeSet<u32>,
}

impl PendingIo {
    pub(crate) fn cost_bits(&self) -> usize {
        self.write_private.len() * 8
    }

    pub(crate) fn write_private(&mut self, addr: u32, len: usize) {
        self.write_private.union_mut(addr..addr + len as u32);
    }

    pub(crate) fn addrs(&self) -> impl Iterator<Item = u32> + '_ {
        self.write_private.iter().flat_map(|r| r.start..r.end)
    }

    pub(crate) fn ranges(&self) -> impl Iterator<Item = Range<u32>> + '_ {
        self.write_private.iter()
    }

    pub(crate) fn clear(&mut self) {
        self.write_private = RangeSet::default();
    }
}

pub(crate) fn ty_width(ty: mpz_vm_ir::ValType) -> usize {
    match ty {
        mpz_vm_ir::ValType::I32 | mpz_vm_ir::ValType::F32 => 32,
        mpz_vm_ir::ValType::I64 | mpz_vm_ir::ValType::F64 => 64,
    }
}

pub(crate) fn prepare_params(params: &[Param]) -> Result<usize> {
    let mut bits = 0;
    for (i, p) in params.iter().enumerate() {
        let ty = match p {
            Param::Private(v) => v.ty(),
            Param::Blind(ty) => *ty,
            Param::Public(_) => continue,
        };
        if matches!(ty, mpz_vm_ir::ValType::F32 | mpz_vm_ir::ValType::F64) {
            return Err(ZkVmError::Unsupported(format!(
                "param {i}: float ({ty:?}) not supported by zk-vm"
            )));
        }
        bits += ty_width(ty);
    }
    Ok(bits)
}

/// The prover's view of an input-commit tape region: each committed bit XORs
/// into the mask in place and yields its authenticated wire directly off the
/// tape. Input commits draw no challenge and fold nothing, so no circuit
/// context is involved.
pub(crate) struct ProverTape<'a> {
    pub(crate) masks: &'a mut [bool],
    pub(crate) macs: &'a [Gf2_128],
    pub(crate) cursor: usize,
}

impl ProverTape<'_> {
    fn bit(&mut self, b: bool) -> Gf2_128 {
        let i = self.cursor;
        self.masks[i] ^= b;
        self.cursor = i + 1;
        mpz_zk_core::prover_wire(self.macs[i], b)
    }
}

/// The verifier's view of an input-commit tape region: each entry yields the
/// key wire adjusted by the received commitment.
pub(crate) struct VerifierTape<'a> {
    pub(crate) keys: &'a [Gf2_128],
    pub(crate) adjust: &'a [bool],
    pub(crate) delta: Gf2_128,
    pub(crate) cursor: usize,
}

impl VerifierTape<'_> {
    fn bit(&mut self) -> Gf2_128 {
        let i = self.cursor;
        self.cursor = i + 1;
        mpz_zk_core::verifier_wire(self.keys[i], self.adjust[i], self.delta)
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(num_params = params.len()))]
pub(crate) fn commit_prover(
    auth: &mut AuthState,
    root_reg_base: Reg,
    params: &[Param],
    pending: &PendingIo,
    global: &Global,
    tape: &mut ProverTape<'_>,
) -> Result<()> {
    for (i, p) in params.iter().enumerate() {
        let (ty, bits): (mpz_vm_ir::ValType, Vec<bool>) = match p {
            Param::Private(v) => (v.ty(), value_le_bits(*v, ty_width(v.ty()))),
            // Prover can't see a blind param, so it commits zero bits; the verifier's
            // adjust supplies the real bit pattern.
            Param::Blind(ty) => (*ty, vec![false; ty_width(*ty)]),
            Param::Public(_) => continue,
        };
        let auth_bits: Vec<Bit> = bits.into_iter().map(|b| Bit(tape.bit(b))).collect();
        auth.regs.set(
            root_reg_base + i as u32,
            AuthValue::from_bits(ty, &auth_bits)?,
        );
    }
    commit_memory_prover(auth, pending, global, tape)
}

pub(crate) fn commit_memory_prover(
    auth: &mut AuthState,
    pending: &PendingIo,
    global: &Global,
    tape: &mut ProverTape<'_>,
) -> Result<()> {
    if pending.cost_bits() == 0 {
        return Ok(());
    }
    let mem = global
        .memory()
        .ok_or(ZkVmError::Core(CoreError::MemoryNotDefined))?;
    for range in pending.ranges() {
        let len = (range.end - range.start) as usize;
        let bytes = mem
            .read_bytes(range.start, len)
            .map_err(ZkVmError::Trap)?
            .to_vec();
        for (i, value) in bytes.into_iter().enumerate() {
            let addr = range.start + i as u32;
            let byte_bits = Byte::new(core::array::from_fn(|bit_idx| {
                Bit(tape.bit((value >> bit_idx) & 1 != 0))
            }));
            auth.memory.set_byte(addr, byte_bits);
        }
    }
    Ok(())
}

#[tracing::instrument(level = "debug", skip_all, fields(num_params = params.len()))]
pub(crate) fn commit_verifier(
    auth: &mut AuthState,
    root_reg_base: Reg,
    params: &[Param],
    pending: &PendingIo,
    tape: &mut VerifierTape<'_>,
) -> Result<()> {
    for (i, p) in params.iter().enumerate() {
        let ty = match p {
            Param::Private(v) => v.ty(),
            Param::Blind(ty) => *ty,
            Param::Public(_) => continue,
        };
        let width = ty_width(ty);
        let auth_bits: Vec<Bit> = (0..width).map(|_| Bit(tape.bit())).collect();
        auth.regs.set(
            root_reg_base + i as u32,
            AuthValue::from_bits(ty, &auth_bits)?,
        );
    }
    commit_memory_verifier(auth, pending, tape);
    Ok(())
}

pub(crate) fn commit_memory_verifier(
    auth: &mut AuthState,
    pending: &PendingIo,
    tape: &mut VerifierTape<'_>,
) {
    for addr in pending.addrs() {
        let byte_bits = Byte::new(core::array::from_fn(|_| Bit(tape.bit())));
        auth.memory.set_byte(addr, byte_bits);
    }
}

pub(crate) fn value_le_bits(v: Value, width: usize) -> Vec<bool> {
    let bytes = v.to_le_bytes();
    (0..width)
        .map(|i| (bytes[i / 8] >> (i % 8)) & 1 != 0)
        .collect()
}
