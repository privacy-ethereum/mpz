use ir::Module;
use mpz_vm_core_new::{Param, Vm, Write, ideal::Instance};

use crate::{
    bench::{BenchOutput, CallSpec, find_heap_base, run_call},
    register_benchmark,
};

static FIXTURE: &[u8] = include_bytes!("../../../profile-bench-programs/fixtures/sample.json");

fn run(module: &Module) -> BenchOutput {
    let heap_base = find_heap_base(module);
    let json_ptr = heap_base;
    let json_len = FIXTURE.len() as i32;

    let mut instance_a = Instance::with_tracing(module.clone()).unwrap();
    let mut instance_b = Instance::new(module.clone()).unwrap();

    instance_a.write(json_ptr, Write::Private(FIXTURE)).unwrap();
    instance_b
        .write(json_ptr, Write::Blind(FIXTURE.len()))
        .unwrap();

    run_call(
        &mut instance_a,
        &mut instance_b,
        CallSpec {
            export: "json_parse",
            params_a: vec![
                Param::public_i32(json_ptr as i32),
                Param::public_i32(json_len),
            ],
            params_b: vec![
                Param::public_i32(json_ptr as i32),
                Param::public_i32(json_len),
            ],
        },
    )
}

register_benchmark!("json_parse", run);
