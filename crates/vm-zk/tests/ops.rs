//! Integration tests that route a PRIVATE value through linear memory under the
//! real prover/verifier protocol — store an authenticated value, load it back
//! (incl. partial widths and sign/zero extension), and check both parties agree.
//!
//! Plain op/result correctness (arithmetic, bitwise, compare, count, div/rem,
//! conversions, call-arg propagation) with private inputs is covered far more
//! broadly by the shared spec harness (`tests/spec.rs`), which runs the whole
//! WASM corpus under all-public, per-argument-private, all-private, and
//! alternating passes; only the store→load wire-routing of a private value is
//! kept here as a focused diagnostic.

mod common;

use futures::{executor::block_on, future::join};
use mpz_common::context::test_st_context;
use mpz_vm_ir::{ExportKind, Module};
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core_new::{Param, Trap, Vm, value::Value};
use mpz_vm_zk::{Prover, Verifier, ZkVmError};
use rand::{SeedableRng, rngs::StdRng};

fn func_idx(module: &Module, name: &str) -> u32 {
    module
        .exports()
        .iter()
        .find_map(|e| match e.kind {
            ExportKind::Func(idx) if e.name == name => Some(idx),
            _ => None,
        })
        .expect("function should be exported")
}

/// A blind param of the same type as `v`, for the verifier side.
fn blind_of(v: &Value) -> Param {
    Param::Blind(v.ty())
}

/// Run `func` on both sides: the prover supplies `inputs` as PRIVATE values,
/// the verifier supplies matching BLIND params. Asserts both sides return
/// `expected`.
fn run_private(wat: &str, func: &str, inputs: &[Value], expected: Value) {
    common::init_tracing();
    let binary = wat::parse_str(wat).expect("valid WAT");
    let module = Module::parse(&binary).expect("valid module");
    let idx = func_idx(&module, func);

    let mut rng = StdRng::seed_from_u64(0);
    let mut delta: mpz_core::Block = rand::Rng::random(&mut rng);
    delta.set_lsb(true);
    let (svole_sender, svole_receiver) = ideal_rcot(rand::Rng::random(&mut rng), delta);

    let mut prover = Prover::new(module.clone(), svole_receiver).unwrap();
    let mut verifier = Verifier::new(module, svole_sender).unwrap();

    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);

    let p_params: Vec<Param> = inputs.iter().cloned().map(Param::Private).collect();
    let v_params: Vec<Param> = inputs.iter().map(blind_of).collect();

    let (result_p, result_v) = block_on(join(
        async { prover.call(&mut ctx_p, idx, p_params).await.unwrap() },
        async { verifier.call(&mut ctx_v, idx, v_params).await.unwrap() },
    ));

    assert_eq!(result_p, Some(expected.clone()), "prover result for `{func}`");
    assert_eq!(result_v, Some(expected), "verifier result for `{func}`");
}

/// A module that stores its private param at a fixed address and loads it back:
/// `(func (param ty) (result ty) i32.const 16 local.get 0 <store> i32.const 16 <load>)`.
fn mem_roundtrip_module(ty: &str, store: &str, load: &str) -> String {
    format!(
        "(module (memory 1) \
         (func $f (export \"f\") (param {ty}) (result {ty}) \
         i32.const 16 local.get 0 {store} \
         i32.const 16 {load}))"
    )
}

#[test]
fn i32_mem_roundtrip_private() {
    let wat = mem_roundtrip_module("i32", "i32.store", "i32.load");
    run_private(&wat, "f", &[Value::I32(-123456)], Value::I32(-123456));
}

#[test]
fn i64_mem_roundtrip_private() {
    let wat = mem_roundtrip_module("i64", "i64.store", "i64.load");
    run_private(
        &wat,
        "f",
        &[Value::I64(0x0123_4567_89ab_cdef)],
        Value::I64(0x0123_4567_89ab_cdef),
    );
}

#[test]
fn i32_mem_partial_widths_private() {
    // store8 then load8_u / load8_s of 0x80 -> 128 (zero) / -128 (sign).
    let z = mem_roundtrip_module("i32", "i32.store8", "i32.load8_u");
    run_private(&z, "f", &[Value::I32(0x80)], Value::I32(0x80));
    let s = mem_roundtrip_module("i32", "i32.store8", "i32.load8_s");
    run_private(&s, "f", &[Value::I32(0x80)], Value::I32(-128));
    // store16 then load16_s of 0x8000 -> -32768.
    let s16 = mem_roundtrip_module("i32", "i32.store16", "i32.load16_s");
    run_private(&s16, "f", &[Value::I32(0x8000)], Value::I32(-32768));
}

#[test]
fn i64_mem_partial_widths_private() {
    // store32 then load32_s of 0x8000_0000 -> sign-extended to i64.
    let s = mem_roundtrip_module("i64", "i64.store32", "i64.load32_s");
    run_private(&s, "f", &[Value::I64(0x8000_0000)], Value::I64(-0x8000_0000));
    let u = mem_roundtrip_module("i64", "i64.store32", "i64.load32_u");
    run_private(&u, "f", &[Value::I64(0x8000_0000)], Value::I64(0x8000_0000));
}

/// Run `func` on both sides expecting it to trap. The prover holds the operands
/// and self-discovers the trap; the verifier's operands are blind, so it cannot
/// decide the trap locally and must detect it by matching the prover's announced
/// trap index against the emitted (could-trap) directive. Asserts both sides
/// surface `expected`.
fn run_private_trap(wat: &str, func: &str, inputs: &[Value], expected: Trap) {
    common::init_tracing();
    let binary = wat::parse_str(wat).expect("valid WAT");
    let module = Module::parse(&binary).expect("valid module");
    let idx = func_idx(&module, func);

    let mut rng = StdRng::seed_from_u64(0);
    let mut delta: mpz_core::Block = rand::Rng::random(&mut rng);
    delta.set_lsb(true);
    let (svole_sender, svole_receiver) = ideal_rcot(rand::Rng::random(&mut rng), delta);

    let mut prover = Prover::new(module.clone(), svole_receiver).unwrap();
    let mut verifier = Verifier::new(module, svole_sender).unwrap();

    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);

    let p_params: Vec<Param> = inputs.iter().cloned().map(Param::Private).collect();
    let v_params: Vec<Param> = inputs.iter().map(blind_of).collect();

    let (result_p, result_v) = block_on(join(
        async { prover.call(&mut ctx_p, idx, p_params).await },
        async { verifier.call(&mut ctx_v, idx, v_params).await },
    ));

    match result_p {
        Err(ZkVmError::Trap(t)) => assert_eq!(t, expected, "prover trap for `{func}`"),
        other => panic!("prover should trap with {expected:?}, got {other:?}"),
    }
    match result_v {
        Err(ZkVmError::Trap(t)) => assert_eq!(t, expected, "verifier trap for `{func}`"),
        other => panic!("verifier should trap with {expected:?}, got {other:?}"),
    }
}

#[test]
fn div_u_by_zero_traps_private() {
    let wat = "(module (func $f (export \"f\") (param i32 i32) (result i32) \
               local.get 0 local.get 1 i32.div_u))";
    run_private_trap(wat, "f", &[Value::I32(6), Value::I32(0)], Trap::DivideByZero);
}

#[test]
fn div_s_overflow_traps_private() {
    // i32::MIN / -1 overflows; the verifier needs both blind operands' trap to
    // be announced, exercising the needs-lhs path.
    let wat = "(module (func $f (export \"f\") (param i32 i32) (result i32) \
               local.get 0 local.get 1 i32.div_s))";
    run_private_trap(
        wat,
        "f",
        &[Value::I32(i32::MIN), Value::I32(-1)],
        Trap::IntegerOverflow,
    );
}
