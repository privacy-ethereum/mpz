use futures::{executor::block_on, future::join};
use ir::ValType;
use mpz_common::{Flush, context::test_st_context, future::Output};
use mpz_ot::{
    ideal::rcot::ideal_rcot,
    rcot::{RCOTReceiver, RCOTSender},
};
use mpz_vm_core_new::{Module, Param, Value};
use mpz_zk_core_new::{Prover, Verifier};

// Simple WAT without imports - just public values
static SIMPLE_WAT: &[u8] = br#"
(module
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )
)
"#;

// WAT with decode import for private values
static DECODE_WAT: &[u8] = br#"
(module
  (import "mpz" "decode_i32" (func $decode_i32 (param i32) (result i32)))
  (func (export "add_decoded") (param i32 i32) (result i32)
    local.get 0
    call $decode_i32
    local.get 1
    call $decode_i32
    i32.add
  )
)
"#;

// WAT that does encoded arithmetic THEN decodes the result
static ENCODED_ARITH_WAT: &[u8] = br#"
(module
  (import "mpz" "decode_i32" (func $decode_i32 (param i32) (result i32)))
  (func (export "encoded_add") (param i32 i32) (result i32)
    local.get 0  ;; encoded value
    local.get 1  ;; encoded value
    i32.add      ;; encoded arithmetic!
    call $decode_i32  ;; decode the result
  )
)
"#;

#[test]
fn test_public_values() {
    let delta = rand::random();
    let (mut rcot_v, mut rcot_p) = ideal_rcot(rand::random(), delta);
    let (mut ctx_p, mut ctx_v) = test_st_context(8);

    rcot_v.alloc(1000).unwrap();
    rcot_p.alloc(1000).unwrap();

    block_on(join(
        async {
            rcot_p.flush(&mut ctx_p).await.unwrap();
        },
        async {
            rcot_v.flush(&mut ctx_v).await.unwrap();
        },
    ));

    let module = Module::parse(&wat::parse_bytes(SIMPLE_WAT).unwrap()).unwrap();
    let mut vm_p = Prover::new(module.clone(), rcot_p).unwrap();
    let mut vm_v = Verifier::new(module, rcot_v).unwrap();

    block_on(join(
        async {
            // Prover uses public values
            let mut promise = vm_p
                .call(
                    0,
                    vec![
                        Param::Public(Value::I32(10)),
                        Param::Public(Value::I32(32)),
                    ],
                )
                .unwrap();
            vm_p.flush(&mut ctx_p).await.unwrap();
            let output = promise.try_recv().unwrap().unwrap().unwrap();
            assert_eq!(output, Value::I32(42)); // 10 + 32 = 42
        },
        async {
            // Verifier uses same public values
            let mut promise = vm_v
                .call(
                    0,
                    vec![
                        Param::Public(Value::I32(10)),
                        Param::Public(Value::I32(32)),
                    ],
                )
                .unwrap();
            vm_v.flush(&mut ctx_v).await.unwrap();
            let output = promise.try_recv().unwrap().unwrap().unwrap();
            assert_eq!(output, Value::I32(42)); // 10 + 32 = 42
        },
    ));
}

#[test]
fn test_private_values() {
    let delta = rand::random();
    let (mut rcot_v, mut rcot_p) = ideal_rcot(rand::random(), delta);
    let (mut ctx_p, mut ctx_v) = test_st_context(8);

    rcot_v.alloc(1000).unwrap();
    rcot_p.alloc(1000).unwrap();

    block_on(join(
        async {
            rcot_p.flush(&mut ctx_p).await.unwrap();
        },
        async {
            rcot_v.flush(&mut ctx_v).await.unwrap();
        },
    ));

    let module = Module::parse(&wat::parse_bytes(DECODE_WAT).unwrap()).unwrap();
    let mut vm_p = Prover::new(module.clone(), rcot_p).unwrap();
    let mut vm_v = Verifier::new(module, rcot_v).unwrap();

    block_on(join(
        async {
            // Prover uses private values - func 1 (func 0 is the import)
            let mut promise = vm_p
                .call(
                    1,
                    vec![
                        Param::Private(Value::I32(10)),
                        Param::Private(Value::I32(32)),
                    ],
                )
                .unwrap();
            vm_p.flush(&mut ctx_p).await.unwrap();
            let output = promise.try_recv().unwrap().unwrap().unwrap();
            assert_eq!(output, Value::I32(42)); // 10 + 32 = 42
        },
        async {
            // Verifier uses blind values (doesn't know the actual values) - func 1
            let mut promise = vm_v
                .call(
                    1,
                    vec![
                        Param::Blind(ValType::I32),
                        Param::Blind(ValType::I32),
                    ],
                )
                .unwrap();
            vm_v.flush(&mut ctx_v).await.unwrap();
            // Verifier doesn't know the actual values yet - just check it completes
            // (once decode proof exchange is implemented, verifier will learn the output)
            let output = promise.try_recv().unwrap().unwrap();
            // For now the verifier just computes with Keys pointer bits
            // which gives garbage - that's expected until we implement proper decode
            assert!(output.is_some());
        },
    ));
}

#[test]
fn test_encoded_arithmetic() {
    let delta = rand::random();
    let (mut rcot_v, mut rcot_p) = ideal_rcot(rand::random(), delta);
    let (mut ctx_p, mut ctx_v) = test_st_context(8);

    rcot_v.alloc(1000).unwrap();
    rcot_p.alloc(1000).unwrap();

    block_on(join(
        async {
            rcot_p.flush(&mut ctx_p).await.unwrap();
        },
        async {
            rcot_v.flush(&mut ctx_v).await.unwrap();
        },
    ));

    let module = Module::parse(&wat::parse_bytes(ENCODED_ARITH_WAT).unwrap()).unwrap();
    let mut vm_p = Prover::new(module.clone(), rcot_p).unwrap();
    let mut vm_v = Verifier::new(module, rcot_v).unwrap();

    block_on(join(
        async {
            // Prover does encoded arithmetic then decodes
            let mut promise = vm_p
                .call(
                    1,
                    vec![
                        Param::Private(Value::I32(10)),
                        Param::Private(Value::I32(32)),
                    ],
                )
                .unwrap();
            vm_p.flush(&mut ctx_p).await.unwrap();
            let output = promise.try_recv().unwrap().unwrap().unwrap();
            assert_eq!(output, Value::I32(42)); // 10 + 32 = 42
        },
        async {
            // Verifier
            let mut promise = vm_v
                .call(
                    1,
                    vec![
                        Param::Blind(ValType::I32),
                        Param::Blind(ValType::I32),
                    ],
                )
                .unwrap();
            vm_v.flush(&mut ctx_v).await.unwrap();
            let output = promise.try_recv().unwrap().unwrap();
            assert!(output.is_some());
        },
    ));
}
