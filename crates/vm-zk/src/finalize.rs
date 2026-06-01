
use mpz_circuits_new::Context;
use mpz_fields::{gf2::Gf2, gf2_128::Gf2_128};
use mpz_vm_core_new::{Reg, value::Value};

use mpz_memory_core_new::AuthState;

use crate::{
    error::{Result, ZkVmError},
    replay::ReplayState,
};

pub(crate) fn bind_output<C>(
    state: &ReplayState,
    exec: &mut C,
    auth: &AuthState,
    output: Option<Value>,
) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: std::fmt::Debug,
{
    let reg = state.output_reg.ok_or(ZkVmError::OutputRegMissing)?;
    let value = output.ok_or(ZkVmError::OutputValueMissing { reg })?;
    assert_output(exec, auth, reg, value)
}

pub(crate) fn assert_output<C>(exec: &mut C, auth: &AuthState, reg: Reg, value: Value) -> Result<()>
where
    C: Context<Wire = Gf2_128, Field = Gf2>,
    C::Error: std::fmt::Debug,
{
    let av = auth
        .regs
        .get(reg)
        .ok_or(ZkVmError::OutputWiresMissing { reg })?;
    if av.ty() != value.ty() {
        return Err(ZkVmError::TypeMismatch {
            reg,
            got: av.ty(),
            expected: value.ty(),
        });
    }
    let bits = av.bits();
    let raw = match value {
        Value::I32(x) => x as u32 as u64,
        Value::I64(x) => x as u64,
        _ => {
            return Err(ZkVmError::Unsupported(
                "float IT-MAC not supported in zk-vm".into(),
            ));
        }
    };
    for (i, b) in bits.iter().enumerate() {
        let expected = Gf2((raw >> i) & 1 != 0);
        exec.assert_const(b.0, expected)
            .map_err(|e| ZkVmError::Internal(format!("assert_const: {e:?}")))?;
    }
    Ok(())
}
