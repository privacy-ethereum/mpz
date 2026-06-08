//! Host-call servicing in the ideal VM: a guest that imports a WASI function
//! must have the call serviced by the embedder. Uses an inline `.wat` module so
//! it runs under a plain `cargo test` with no external build step.

use futures::executor::block_on;
use mpz_common::context::test_st_context;
use mpz_vm_core_new::{Vm, value::Value};
use mpz_vm_ideal::Instance;
use mpz_vm_ir::{ExportKind, Module};

fn func_idx(module: &Module, name: &str) -> u32 {
    module
        .exports()
        .iter()
        .find_map(|e| match e.kind {
            ExportKind::Func(idx) if e.name == name => Some(idx),
            _ => None,
        })
        .expect("export should exist")
}

/// A guest that builds a WASI iovec for a 3-byte string and calls `fd_write` to
/// stdout, returning the call's errno. The ideal VM must service the import (read
/// the iovec, emit the bytes, write `nwritten`) and report success.
#[test]
fn fd_write_host_call_is_serviced() {
    let wat = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory 1)
          (data (i32.const 16) "hi\n")
          (func (export "print") (result i32)
            ;; iovec at addr 0: { ptr = 16, len = 3 }
            (i32.store (i32.const 0) (i32.const 16))
            (i32.store (i32.const 4) (i32.const 3))
            ;; fd_write(fd = 1 (stdout), iovs = 0, iovs_len = 1, nwritten = 8)
            (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))))
    "#;
    let module = Module::parse(&wat::parse_str(wat).expect("valid wat")).expect("valid module");
    let idx = func_idx(&module, "print");

    let mut vm = Instance::new(module).unwrap();
    let (mut ctx, _) = test_st_context(8);

    let out = block_on(vm.call(&mut ctx, idx, vec![])).unwrap();
    assert_eq!(out, Some(Value::I32(0)), "fd_write should report errno 0");
}

/// A guest that reveals a scalar and waits for it. The ideal VM stages the value
/// under a handle on `reveal_i32` and returns it on `reveal_i32_wait`, so the
/// two-phase reveal round-trips to the original value.
#[test]
fn scalar_reveal_round_trips() {
    let wat = r#"
        (module
          (import "vc" "reveal_i32" (func $reveal (param i32) (result i32)))
          (import "vc" "reveal_i32_wait" (func $wait (param i32) (result i32)))
          (func (export "roundtrip") (result i32)
            (call $wait (call $reveal (i32.const 42)))))
    "#;
    let module = Module::parse(&wat::parse_str(wat).expect("valid wat")).expect("valid module");
    let idx = func_idx(&module, "roundtrip");

    let mut vm = Instance::new(module).unwrap();
    let (mut ctx, _) = test_st_context(8);

    let out = block_on(vm.call(&mut ctx, idx, vec![])).unwrap();
    assert_eq!(out, Some(Value::I32(42)), "reveal/wait should return the value");
}

/// A guest that reveals a byte range in memory and then reads it back. The ideal
/// VM marks the range public on `reveal_bytes_wait`; the bytes are already in
/// place, so the subsequent load observes them.
#[test]
fn byte_reveal_marks_range_public() {
    let wat = r#"
        (module
          (import "vc" "reveal_bytes" (func $reveal (param i32 i32) (result i32)))
          (import "vc" "reveal_bytes_wait" (func $wait (param i32)))
          (memory 1)
          (data (i32.const 16) "\07\00\00\00")
          (func (export "reveal_mem") (result i32)
            (call $wait (call $reveal (i32.const 16) (i32.const 4)))
            (i32.load8_u (i32.const 16))))
    "#;
    let module = Module::parse(&wat::parse_str(wat).expect("valid wat")).expect("valid module");
    let idx = func_idx(&module, "reveal_mem");

    let mut vm = Instance::new(module).unwrap();
    let (mut ctx, _) = test_st_context(8);

    let out = block_on(vm.call(&mut ctx, idx, vec![])).unwrap();
    assert_eq!(out, Some(Value::I32(7)), "revealed bytes should be readable");
}
