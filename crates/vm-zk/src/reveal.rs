
use std::ops::Range;

use mpz_circuits_new::Context;
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use mpz_vm_core_new::Memory;

use mpz_memory_core_new::AuthState;

use crate::error::{Result, ZkVmError};

pub(crate) fn reveal_prover<C>(
    exec: &mut C,
    auth: &AuthState,
    memory: &Memory,
    ranges: &[Range<u32>],
) -> Result<Vec<u8>>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: std::fmt::Debug,
{
    let mut cleartext = Vec::new();
    for range in ranges {
        for addr in range.clone() {
            let value = memory.read_bytes(addr, 1).map_err(ZkVmError::Trap)?[0];
            assert_byte(exec, auth, addr, value)?;
            cleartext.push(value);
        }
    }
    Ok(cleartext)
}

pub(crate) fn reveal_verifier<C>(
    exec: &mut C,
    auth: &AuthState,
    ranges: &[Range<u32>],
    cleartext: &[u8],
) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: std::fmt::Debug,
{
    let total: usize = ranges.iter().map(|r| (r.end - r.start) as usize).sum();
    if cleartext.len() != total {
        return Err(ZkVmError::Internal(format!(
            "reveal cleartext length {} != revealed byte count {total}",
            cleartext.len()
        )));
    }
    let mut idx = 0;
    for range in ranges {
        for addr in range.clone() {
            assert_byte(exec, auth, addr, cleartext[idx])?;
            idx += 1;
        }
    }
    Ok(())
}

/// Opens the `bytes` at `[ptr, ptr + bytes.len())` against their committed
/// wires, asserting each byte's MAC equals the disclosed value.
pub(crate) fn assert_bytes<C>(exec: &mut C, auth: &AuthState, ptr: u32, bytes: &[u8]) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: std::fmt::Debug,
{
    for (i, &b) in bytes.iter().enumerate() {
        assert_byte(exec, auth, ptr + i as u32, b)?;
    }
    Ok(())
}

fn assert_byte<C>(exec: &mut C, auth: &AuthState, addr: u32, value: u8) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: std::fmt::Debug,
{
    let byte = auth
        .memory
        .get_byte(addr)
        .ok_or(ZkVmError::MemAuthMissing { addr })?;
    for (i, bit) in byte.bits().iter().enumerate() {
        let expected = Gf2((value >> i) & 1 != 0);
        exec.assert_const(bit.0, expected)
            .map_err(|e| ZkVmError::Internal(format!("assert_const: {e:?}")))?;
    }
    Ok(())
}
