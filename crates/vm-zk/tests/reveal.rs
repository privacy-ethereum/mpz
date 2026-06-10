//! End-to-end tests of guest VCI reveal: a program that reveals private data
//! must disclose it to the blind verifier, with the disclosure bound to the
//! committed witness. Each scalar case runs the same program on the prover
//! (with a private input) and the blind verifier, asserting both return the
//! expected value — so a verifier that failed to learn the reveal, or learned a
//! wrong value, fails the test.

mod common;

use futures::{executor::block_on, future::join};
use mpz_common::context::test_st_context;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{Param, Vm, value::Value};
use mpz_vm_ir::{ExportKind, Module, ValType};
use mpz_vm_zk::{Prover, Verifier};
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

fn blind(v: &Value) -> Param {
    match v {
        Value::I32(_) => Param::Blind(ValType::I32),
        Value::I64(_) => Param::Blind(ValType::I64),
        Value::F32(_) => Param::Blind(ValType::F32),
        Value::F64(_) => Param::Blind(ValType::F64),
    }
}

/// Runs `func` on the prover (with `inputs` as private parameters) and the
/// blind verifier (the same inputs as blinds), under `chunk_cap`, asserting
/// both return `expected`. The verifier assertion is the substance: it only
/// holds if the reveal disclosed the value to the party that never held it.
fn run(wat: &str, func: &str, inputs: &[Value], expected: Value, chunk_cap: Option<usize>) {
    common::init_tracing();
    let module = Module::parse(&wat::parse_str(wat).expect("valid WAT")).expect("valid module");
    let idx = func_idx(&module, func);

    let mut rng = StdRng::seed_from_u64(0);
    let mut delta: mpz_core::Block = rand::Rng::random(&mut rng);
    delta.set_lsb(true);
    let (svole_sender, svole_receiver) = ideal_rcot(rand::Rng::random(&mut rng), delta);

    let mut prover = Prover::new(module.clone(), svole_receiver)
        .unwrap()
        .with_chunk_cap(chunk_cap);
    let mut verifier = Verifier::new(module, svole_sender)
        .unwrap()
        .with_chunk_cap(chunk_cap);

    let (mut ctx_p, mut ctx_v) = test_st_context(1024 * 1024);

    let p_params: Vec<Param> = inputs.iter().cloned().map(Param::Private).collect();
    let v_params: Vec<Param> = inputs.iter().map(blind).collect();

    let (result_p, result_v) = block_on(join(
        async { prover.call(&mut ctx_p, idx, p_params).await.unwrap() },
        async { verifier.call(&mut ctx_v, idx, v_params).await.unwrap() },
    ));

    assert_eq!(result_p, Some(expected), "prover result for `{func}`");
    assert_eq!(
        result_v,
        Some(expected),
        "verifier must learn the reveal for `{func}`"
    );
}

/// `disclose(x)` reveals its private argument and returns the revealed value:
/// the baseline scalar disclosure.
#[test]
fn scalar_reveal_discloses_private_input() {
    let wat = r#"
        (module
          (import "vc" "reveal_i32" (func $reveal (param i32) (result i32)))
          (import "vc" "reveal_i32_wait" (func $wait (param i32) (result i32)))
          (func (export "disclose") (param i32) (result i32)
            (call $wait (call $reveal (local.get 0)))))
    "#;
    run(wat, "disclose", &[Value::I32(42)], Value::I32(42), None);
}

/// A revealed value is public, so the program can branch on it — the only way
/// to get data-dependent control flow in zk-vm, which rejects private
/// branching. If the reveal failed to make the value public, the verifier would
/// block on the branch and the call would error.
#[test]
fn revealed_value_drives_a_branch() {
    let wat = r#"
        (module
          (import "vc" "reveal_i32" (func $reveal (param i32) (result i32)))
          (import "vc" "reveal_i32_wait" (func $wait (param i32) (result i32)))
          (func (export "branch") (param i32) (result i32)
            (local $x i32)
            (local.set $x (call $wait (call $reveal (local.get 0))))
            (if (result i32) (i32.gt_s (local.get $x) (i32.const 5))
              (then (i32.const 100))
              (else (i32.const 200)))))
    "#;
    run(wat, "branch", &[Value::I32(7)], Value::I32(100), None);
    run(wat, "branch", &[Value::I32(3)], Value::I32(200), None);
}

/// With one op per chunk, the reveal and its wait land in different chunks, so
/// the disclosed payload must survive across chunk boundaries: announced when
/// the reveal is captured, retrieved when the wait is captured a chunk or more
/// later.
#[test]
fn reveal_and_wait_span_chunks() {
    let wat = r#"
        (module
          (import "vc" "reveal_i32" (func $reveal (param i32) (result i32)))
          (import "vc" "reveal_i32_wait" (func $wait (param i32) (result i32)))
          (func (export "spanned") (param i32) (result i32)
            (local $h i32)
            (local.set $h (call $reveal (local.get 0)))
            (drop (i32.add (i32.const 1) (i32.const 2)))
            (drop (i32.add (i32.const 3) (i32.const 4)))
            (drop (i32.add (i32.const 5) (i32.const 6)))
            (call $wait (local.get $h))))
    "#;
    run(wat, "spanned", &[Value::I32(99)], Value::I32(99), Some(1));
}

/// Two reveals are staged before either wait, so they take distinct ids and the
/// waits resolve them by handle — exercising the reveal-id keying and the
/// one-action-per-import-call ordering that replay relies on.
#[test]
fn two_staged_reveals_resolve_by_handle() {
    let wat = r#"
        (module
          (import "vc" "reveal_i32" (func $reveal (param i32) (result i32)))
          (import "vc" "reveal_i32_wait" (func $wait (param i32) (result i32)))
          (func (export "sum") (param i32 i32) (result i32)
            (local $ha i32) (local $hb i32)
            (local.set $ha (call $reveal (local.get 0)))
            (local.set $hb (call $reveal (local.get 1)))
            (i32.add (call $wait (local.get $ha)) (call $wait (local.get $hb)))))
    "#;
    run(
        wat,
        "sum",
        &[Value::I32(10), Value::I32(20)],
        Value::I32(30),
        None,
    );
}

/// `disclose_bytes(x)` stores its private argument to memory, reveals those 4
/// bytes, then reads them back. The blind verifier learns the bytes through the
/// reveal (materialized into its memory on wait) and reads back the same value,
/// with the open bound to the stored witness.
#[test]
fn byte_reveal_discloses_private_memory() {
    common::init_tracing();
    let wat = r#"
        (module
          (import "vc" "reveal_bytes" (func $reveal (param i32 i32) (result i32)))
          (import "vc" "reveal_bytes_wait" (func $wait (param i32)))
          (memory 1)
          (func (export "disclose_bytes") (param i32) (result i32)
            (i32.store (i32.const 0) (local.get 0))
            (call $wait (call $reveal (i32.const 0) (i32.const 4)))
            (i32.load (i32.const 0))))
    "#;
    let secret = 0x1234_5678u32 as i32;
    run(
        wat,
        "disclose_bytes",
        &[Value::I32(secret)],
        Value::I32(secret),
        None,
    );
}
