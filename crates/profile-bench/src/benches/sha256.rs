use mpz_vm_core::{Param, Write};
use mpz_vm_ir::Module;
use profile_core::Tracer;

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

    let mut tracer = Tracer::new(module.clone()).unwrap();
    tracer.write(msg_ptr, Write::Private(&msg_data)).unwrap();

    run_call(
        tracer,
        CallSpec {
            export: "sha256",
            params: vec![
                Param::public_i32(msg_ptr as i32),
                Param::public_i32(msg_len),
                Param::public_i32(out_ptr as i32),
            ],
        },
    )
}

register_benchmark!("sha256", run);
