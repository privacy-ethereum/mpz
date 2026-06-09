use mpz_vm_core::{Param, Write};
use mpz_vm_ir::Module;
use profile_core::Tracer;

use crate::{
    bench::{BenchOutput, CallSpec, find_heap_base, run_call},
    register_benchmark,
};

static FIXTURE: &[u8] = include_bytes!("../../../profile-bench-programs/fixtures/sample.json");

fn run(module: &Module) -> BenchOutput {
    let heap_base = find_heap_base(module);
    let json_ptr = heap_base;
    let json_len = FIXTURE.len() as i32;

    let mut tracer = Tracer::new(module.clone()).unwrap();
    tracer.write(json_ptr, Write::Private(FIXTURE)).unwrap();

    run_call(
        tracer,
        CallSpec {
            export: "json_parse",
            params: vec![
                Param::public_i32(json_ptr as i32),
                Param::public_i32(json_len),
            ],
        },
    )
}

register_benchmark!("json_parse", run);
