//! Integration tests using the vm-core-tests WASM module.

use futures::{executor::block_on, future::join};
use ir::{ExportKind, ValType};
use mpz_common::context::test_st_context;
use mpz_vm_core_new::{Module, Param, Vm, Write, ideal::Instance, value::Value};

/// Path to the vm-core-tests WASM binary (wasm32-unknown-unknown).
const WASM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32-unknown-unknown/release/vm_core_tests.wasm"
);

/// Path to the vm-core-tests WASM binary (wasm32-wasip1).
const WASM_PATH_WASI: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32-wasip1/release/vm_core_tests.wasm"
);

fn load_module() -> Module {
    let bytes = std::fs::read(WASM_PATH).expect("vm_core_tests.wasm should exist - run: cargo build -p vm-core-tests --target wasm32-unknown-unknown --release");
    Module::parse(&bytes).expect("module should parse")
}

fn load_module_wasi() -> Module {
    let bytes = std::fs::read(WASM_PATH_WASI).expect("vm_core_tests.wasm (wasi) should exist - run: cargo build -p vm-core-tests --target wasm32-wasip1 --release");
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

    let mut vm_a = Instance::new(module.clone()).unwrap();
    let mut vm_b = Instance::new(module).unwrap();
    let (ctx_a, ctx_b) = test_st_context(8);

    block_on(join(
        async {
            let mut ctx = ctx_a;
            let args = vec![
                Param::Private(Value::from(a)),
                Param::Blind(ValType::I32),
                Param::Public(Value::from(n)),
            ];
            let out = vm_a.call(&mut ctx, func_idx as u32, args).await.unwrap();

            assert_eq!(out, Some(Value::I32(expected)));
        },
        async {
            let mut ctx = ctx_b;
            let args = vec![
                Param::Blind(ValType::I32),
                Param::Private(Value::from(b)),
                Param::Public(Value::from(n)),
            ];
            let out = vm_b.call(&mut ctx, func_idx as u32, args).await.unwrap();

            assert_eq!(out, Some(Value::I32(expected)));
        },
    ));
}

#[test]
fn test_preprocess() {
    let a = 3i32;

    let module = load_module();
    let func_idx = get_func_idx(&module, "preprocess");

    let mut vm_a = Instance::new(module.clone()).unwrap();
    let mut vm_b = Instance::new(module).unwrap();
    let (ctx_a, ctx_b) = test_st_context(8);

    block_on(join(
        async {
            let mut ctx = ctx_a;
            let args = vec![Param::Private(Value::from(a))];
            let out = vm_a.call(&mut ctx, func_idx as u32, args).await.unwrap();

            assert!(out.is_none())
        },
        async {
            let mut ctx = ctx_b;
            let args = vec![Param::Blind(ValType::I32)];
            let out = vm_b.call(&mut ctx, func_idx as u32, args).await.unwrap();

            assert!(out.is_none())
        },
    ));
}

#[test]
fn test_aes() {
    let key = [1u8; 16];
    let msg = [2u8; 16];

    let module = load_module();
    let aes_idx = get_func_idx(&module, "aes");
    let realloc_idx = get_func_idx(&module, "cabi_realloc");

    let mut vm_a = Instance::new(module.clone()).unwrap();
    let mut vm_b = Instance::new(module).unwrap();
    let (ctx_a, ctx_b) = test_st_context(8);

    block_on(join(
        async {
            let mut ctx = ctx_a;

            // Allocate memory for key (16 bytes, align 1)
            let key_ptr = vm_a
                .call(
                    &mut ctx,
                    realloc_idx as u32,
                    vec![
                        Param::public_i32(0),  // old_ptr
                        Param::public_i32(0),  // old_len
                        Param::public_i32(1),  // align
                        Param::public_i32(16), // new_len
                    ],
                )
                .await
                .unwrap()
                .unwrap()
                .as_i32()
                .unwrap() as u32;

            // Allocate memory for msg (16 bytes, align 1)
            let msg_ptr = vm_a
                .call(
                    &mut ctx,
                    realloc_idx as u32,
                    vec![
                        Param::public_i32(0),
                        Param::public_i32(0),
                        Param::public_i32(1),
                        Param::public_i32(16),
                    ],
                )
                .await
                .unwrap()
                .unwrap()
                .as_i32()
                .unwrap() as u32;

            // Mark key as private (we have it), msg as blind (peer has it)
            vm_a.write(key_ptr, Write::Private(&key)).unwrap();
            vm_a.write(msg_ptr, Write::Blind(16)).unwrap();

            // Call aes with the pointers
            let out = vm_a
                .call(
                    &mut ctx,
                    aes_idx as u32,
                    vec![
                        Param::public_i32(key_ptr as i32),
                        Param::public_i32(msg_ptr as i32),
                    ],
                )
                .await
                .unwrap();

            assert!(out.is_none());
        },
        async {
            let mut ctx = ctx_b;

            // Allocate memory for key (16 bytes, align 1)
            let key_ptr = vm_b
                .call(
                    &mut ctx,
                    realloc_idx as u32,
                    vec![
                        Param::public_i32(0),
                        Param::public_i32(0),
                        Param::public_i32(1),
                        Param::public_i32(16),
                    ],
                )
                .await
                .unwrap()
                .unwrap()
                .as_i32()
                .unwrap() as u32;

            // Allocate memory for msg (16 bytes, align 1)
            let msg_ptr = vm_b
                .call(
                    &mut ctx,
                    realloc_idx as u32,
                    vec![
                        Param::public_i32(0),
                        Param::public_i32(0),
                        Param::public_i32(1),
                        Param::public_i32(16),
                    ],
                )
                .await
                .unwrap()
                .unwrap()
                .as_i32()
                .unwrap() as u32;

            // Mark key as blind (peer has it), msg as private (we have it)
            vm_b.write(key_ptr, Write::Blind(16)).unwrap();
            vm_b.write(msg_ptr, Write::Private(&msg)).unwrap();

            // Call aes with the pointers
            let out = vm_b
                .call(
                    &mut ctx,
                    aes_idx as u32,
                    vec![
                        Param::public_i32(key_ptr as i32),
                        Param::public_i32(msg_ptr as i32),
                    ],
                )
                .await
                .unwrap();

            assert!(out.is_none());
        },
    ));
}

#[test]
fn test_println() {
    let module = load_module_wasi();
    let func_idx = get_func_idx(&module, "test_print");

    let mut vm = Instance::new(module).unwrap();
    let (mut ctx, _) = test_st_context(8);

    let out = block_on(vm.call(&mut ctx, func_idx as u32, vec![])).unwrap();
    assert!(out.is_none());
}

#[test]
fn test_json_parse() {
    static JSON_FIXTURE: &[u8] =
        include_bytes!("../../../crates/vm-core-tests/fixtures/sample.json");
    let json_data = JSON_FIXTURE.to_vec();
    let json_len = json_data.len();

    let module = load_module();
    let json_parse_idx = get_func_idx(&module, "json_parse");
    let realloc_idx = get_func_idx(&module, "cabi_realloc");

    let mut vm_a = Instance::new(module.clone()).unwrap();
    let mut vm_b = Instance::new(module).unwrap();
    let (ctx_a, ctx_b) = test_st_context(8);

    block_on(join(
        async {
            let mut ctx = ctx_a;

            let json_ptr = vm_a
                .call(
                    &mut ctx,
                    realloc_idx as u32,
                    vec![
                        Param::public_i32(0),
                        Param::public_i32(0),
                        Param::public_i32(1),
                        Param::public_i32(json_len as i32),
                    ],
                )
                .await
                .unwrap()
                .unwrap()
                .as_i32()
                .unwrap() as u32;

            vm_a.write(json_ptr, Write::Private(&json_data)).unwrap();

            let out = vm_a
                .call(
                    &mut ctx,
                    json_parse_idx as u32,
                    vec![
                        Param::public_i32(json_ptr as i32),
                        Param::public_i32(json_len as i32),
                    ],
                )
                .await
                .unwrap();

            assert_eq!(out, Some(Value::I32(0)));
        },
        async {
            let mut ctx = ctx_b;

            let json_ptr = vm_b
                .call(
                    &mut ctx,
                    realloc_idx as u32,
                    vec![
                        Param::public_i32(0),
                        Param::public_i32(0),
                        Param::public_i32(1),
                        Param::public_i32(json_len as i32),
                    ],
                )
                .await
                .unwrap()
                .unwrap()
                .as_i32()
                .unwrap() as u32;

            vm_b.write(json_ptr, Write::Blind(json_len)).unwrap();

            let out = vm_b
                .call(
                    &mut ctx,
                    json_parse_idx as u32,
                    vec![
                        Param::public_i32(json_ptr as i32),
                        Param::public_i32(json_len as i32),
                    ],
                )
                .await
                .unwrap();

            assert_eq!(out, Some(Value::I32(0)));
        },
    ));
}
