use ir::Module;
use mpz_vm_core_new::{Param, Vm, Write, ideal::Instance};

use crate::{
    bench::{BenchOutput, CallSpec, find_heap_base, run_call},
    register_benchmark,
};

fn run(module: &Module) -> BenchOutput {
    let heap_base = find_heap_base(module);
    let msg_data = vec![0xABu8; 2048];
    let msg_ptr = heap_base;
    let msg_len = msg_data.len() as i32;
    let out_ptr = heap_base + msg_data.len() as u32;

    let mut instance_a = Instance::with_tracing(module.clone()).unwrap();
    let mut instance_b = Instance::new(module.clone()).unwrap();

    instance_a
        .write(msg_ptr, Write::Private(&msg_data))
        .unwrap();
    instance_b
        .write(msg_ptr, Write::Blind(msg_data.len()))
        .unwrap();

    run_call(
        &mut instance_a,
        &mut instance_b,
        CallSpec {
            export: "sha256",
            params_a: vec![
                Param::public_i32(msg_ptr as i32),
                Param::public_i32(msg_len),
                Param::public_i32(out_ptr as i32),
            ],
            params_b: vec![
                Param::public_i32(msg_ptr as i32),
                Param::public_i32(msg_len),
                Param::public_i32(out_ptr as i32),
            ],
        },
    )
}

register_benchmark!("sha256", run);
