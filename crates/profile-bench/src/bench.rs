use futures::executor::block_on;
use ir::{ExportKind, Instruction, Module};
use mpz_common::context::test_st_context;
use mpz_vm_core_new::{
    Param, Vm, VmError,
    ideal::{Instance, TraceEvent},
};

pub struct BenchOutput {
    pub trace: Vec<TraceEvent>,
    pub outcome: String,
}

pub struct BenchmarkDef {
    pub name: &'static str,
    pub run: fn(&Module) -> BenchOutput,
}

inventory::collect!(BenchmarkDef);

#[macro_export]
macro_rules! register_benchmark {
    ($name:literal, $run:expr) => {
        inventory::submit! {
            $crate::bench::BenchmarkDef {
                name: $name,
                run: $run,
            }
        }
    };
}

pub struct CallSpec {
    pub export: &'static str,
    pub params_a: Vec<Param>,
    pub params_b: Vec<Param>,
}

pub fn find_heap_base(module: &Module) -> u32 {
    for export in module.exports() {
        if export.name == "__heap_base" {
            if let ExportKind::Global(idx) = export.kind {
                let global = &module.globals()[idx as usize];
                if let Some(Instruction::I32Const { val, .. }) = global.init.first() {
                    return *val as u32;
                }
            }
        }
    }
    eprintln!("Warning: __heap_base not found, using 65536 as fallback");
    65536
}

fn resolve_export(module: &Module, name: &str) -> Option<u32> {
    for export in module.exports() {
        if export.name == name {
            if let ExportKind::Func(idx) = export.kind {
                return Some(idx);
            }
        }
    }
    None
}

pub fn run_call(
    instance_a: &mut Instance,
    instance_b: &mut Instance,
    spec: CallSpec,
) -> BenchOutput {
    let func_idx = match resolve_export(instance_a.module(), spec.export) {
        Some(idx) => idx,
        None => {
            return BenchOutput {
                trace: vec![],
                outcome: format!("export '{}' not found", spec.export),
            };
        }
    };

    let (mut ctx_a, mut ctx_b) = test_st_context(8192);

    let outcome = match block_on(futures::future::try_join(
        instance_a.call(&mut ctx_a, func_idx, spec.params_a),
        instance_b.call(&mut ctx_b, func_idx, spec.params_b),
    )) {
        Ok((result_a, _result_b)) => match result_a {
            Some(val) => format!("ok (returned {:?})", val),
            None => "ok".to_string(),
        },
        Err(VmError::Trap(trap)) => format!("TRAP: {}", trap),
        Err(e) => format!("ERROR: {}", e),
    };

    let trace = instance_a
        .trace_log()
        .map(|t| t.to_vec())
        .unwrap_or_default();

    BenchOutput { trace, outcome }
}
