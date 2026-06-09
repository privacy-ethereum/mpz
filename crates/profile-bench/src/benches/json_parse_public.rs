use mpz_vm_core::{Param, Write};
use mpz_vm_ir::Module;
use rangeset::{iter::RangeIterator, ops::Set};
use spansy::{Store, json::*};

type RangeSet = rangeset::set::RangeSet<usize>;

use profile_core::Tracer;

use crate::{
    bench::{BenchOutput, CallSpec, find_heap_base, run_call},
    register_benchmark,
};

static FIXTURE: &[u8] = include_bytes!("../../../profile-bench-programs/fixtures/sample.json");

fn run(module: &Module) -> BenchOutput {
    let heap_base = find_heap_base(module);
    let json = spansy::json::parse(FIXTURE).unwrap();

    let mut v = Visitor::default();
    v.visit_value(&json.root);
    let private = v.private;

    let mut tracer = Tracer::new(module.clone()).unwrap();
    write_json(&mut tracer, heap_base, &private);

    run_call(
        tracer,
        CallSpec {
            export: "json_parse",
            params: vec![
                Param::public_i32(heap_base as i32),
                Param::public_i32(FIXTURE.len() as i32),
            ],
        },
    )
}

register_benchmark!("json_parse_public", run);

/// Stages the fixture into the tracer, marking JSON numbers and strings private
/// and everything else (structure, keys, whitespace) public.
fn write_json(tracer: &mut Tracer, ptr: u32, private: &RangeSet) {
    let public = (0..FIXTURE.len()).difference(private).into_set();

    for range in public {
        tracer
            .write(ptr + range.start as u32, Write::Public(&FIXTURE[range]))
            .unwrap();
    }

    for range in private {
        tracer
            .write(ptr + range.start as u32, Write::Private(&FIXTURE[range]))
            .unwrap();
    }
}

#[derive(Default)]
struct Visitor {
    private: RangeSet,
}

impl<S: Store> JsonVisit<S> for Visitor {
    fn visit_number(&mut self, node: &Number<S>) {
        self.private.union_mut(node);
    }

    fn visit_string(&mut self, node: &String<S>) {
        self.private.union_mut(node);
    }
}
