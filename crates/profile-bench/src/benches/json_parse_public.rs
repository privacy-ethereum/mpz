use ir::Module;
use mpz_vm_core_new::{Param, Vm, Write, ideal::Instance};
use rangeset::{
    iter::{IntoRangeIterator, RangeIterator},
    ops::Set,
};
use spansy::{Store, json::*};

type RangeSet = rangeset::set::RangeSet<usize>;

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

    let mut vm_a = Instance::with_tracing(module.clone()).unwrap();
    let mut vm_b = Instance::new(module.clone()).unwrap();

    write_json(&mut vm_a, heap_base, &private, true);
    write_json(&mut vm_b, heap_base, &private, false);

    run_call(
        &mut vm_a,
        &mut vm_b,
        CallSpec {
            export: "json_parse",
            params_a: vec![
                Param::public_i32(heap_base as i32),
                Param::public_i32(FIXTURE.len() as i32),
            ],
            params_b: vec![
                Param::public_i32(heap_base as i32),
                Param::public_i32(FIXTURE.len() as i32),
            ],
        },
    )
}

register_benchmark!("json_parse_public", run);

fn write_json(vm: &mut Instance, ptr: u32, private: &RangeSet, party: bool) {
    let public = (0..FIXTURE.len()).difference(private).into_set();

    for range in public {
        vm.write(ptr + range.start as u32, Write::Public(&FIXTURE[range]))
            .unwrap();
    }

    for range in private {
        if party {
            vm.write(ptr + range.start as u32, Write::Private(&FIXTURE[range]))
                .unwrap();
        } else {
            vm.write(ptr + range.start as u32, Write::Blind(range.len()))
                .unwrap();
        }
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
