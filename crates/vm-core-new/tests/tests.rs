//! Integration tests using the vm-core-tests WASM module.

use aes::cipher::KeyInit;
use futures::{executor::block_on, future::join};
use ir::{ExportKind, ValType};
use mpz_common::{
    context::{test_mt_context, test_st_context},
    future::Output,
};
use mpz_vm_core_new::{Instance, Module, Param, ideal::IdealBackend, value::Value};

/// Path to the vm-core-tests WASM binary.
const WASM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32-unknown-unknown/release/vm_core_tests.wasm"
);

fn load_module() -> Module {
    let bytes = std::fs::read(WASM_PATH).expect("vm_core_tests.wasm should exist - run: cargo build -p vm-core-tests --target wasm32-unknown-unknown --release");
    Module::parse(&bytes).expect("module should parse")
}

fn get_func_idx(module: &Module, name: &str) -> usize {
    module
        .exports()
        .iter()
        .find_map(|e| {
            if let ExportKind::Func(idx) = e.kind
                && e.name == name
            {
                Some(idx as usize)
            } else {
                None
            }
        })
        .expect("function should be in module")
}

#[test]
fn test_mul_exp() {
    let a = 4i32;
    let b = 6i32;
    let n = 10i32;
    let expected = a * b.pow(n as u32);

    let module = load_module();
    let func_idx = get_func_idx(&module, "mul_exp");

    let vm_a = Instance::new(module.clone(), IdealBackend::default()).unwrap();
    let vm_b = Instance::new(module, IdealBackend::default()).unwrap();
    let (ctx_a, ctx_b) = test_st_context(8);

    block_on(join(
        async {
            let mut vm = vm_a;
            let mut ctx = ctx_a;
            let args = vec![
                Param::Private(Value::from(a)),
                Param::Blind(ValType::I32),
                Param::Public(Value::from(n)),
            ];
            let mut promise = vm.call(func_idx as u32, args).unwrap();

            vm.run(&mut ctx).await.unwrap();
            let out = promise.try_recv().unwrap().unwrap().unwrap().unwrap();

            assert_eq!(out, Value::I32(expected));
        },
        async {
            let mut vm = vm_b;
            let mut ctx = ctx_b;
            let args = vec![
                Param::Blind(ValType::I32),
                Param::Private(Value::from(b)),
                Param::Public(Value::from(n)),
            ];
            let mut promise = vm.call(func_idx as u32, args).unwrap();

            vm.run(&mut ctx).await.unwrap();
            let out = promise.try_recv().unwrap().unwrap().unwrap().unwrap();

            assert_eq!(out, Value::I32(expected));
        },
    ));
}

#[test]
fn test_aes() {
    let key = 1;
    let msg = 2;

    let module = load_module();
    let func_idx = get_func_idx(&module, "aes");

    let vm_a = Instance::new(module.clone(), IdealBackend::default()).unwrap();
    let vm_b = Instance::new(module, IdealBackend::default()).unwrap();
    let (ctx_a, ctx_b) = test_st_context(8);

    block_on(join(
        async {
            let mut vm = vm_a;
            let mut ctx = ctx_a;
            let args = vec![Param::Private(Value::from(key)), Param::Blind(ValType::I32)];
            let mut promise = vm.call(func_idx as u32, args).unwrap();

            vm.run(&mut ctx).await.unwrap();
            let out = promise.try_recv().unwrap().unwrap();

            assert!(out.unwrap().is_none())
        },
        async {
            let mut vm = vm_b;
            let mut ctx = ctx_b;
            let args = vec![Param::Blind(ValType::I32), Param::Private(Value::from(msg))];
            let mut promise = vm.call(func_idx as u32, args).unwrap();

            vm.run(&mut ctx).await.unwrap();
            let out = promise.try_recv().unwrap().unwrap();

            assert!(out.unwrap().is_none())
        },
    ));
}
