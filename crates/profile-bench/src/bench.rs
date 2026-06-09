use mpz_vm_ir::Module;

use profile_core::{Outcome, TraceEvent, Tracer, TracerError};

/// The trace and outcome produced by running one benchmark.
pub struct BenchOutput {
    pub trace: Vec<TraceEvent>,
    pub outcome: String,
}

/// A registered benchmark: a name and a closure that runs it on a fresh module.
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

/// The exported function to invoke and the parameters to pass it.
pub struct CallSpec {
    pub export: &'static str,
    pub params: Vec<mpz_vm_core::Param>,
}

/// Reads the value of the module's `__heap_base` global, the first address
/// above static data where the guest's heap begins.
pub fn find_heap_base(module: &Module) -> u32 {
    profile_core::module::heap_base(module).unwrap_or_else(|| {
        eprintln!("Warning: __heap_base not found, using 65536 as fallback");
        65536
    })
}

/// Runs `spec` on `tracer`, returning the recorded trace and a human-readable
/// outcome string.
pub fn run_call(mut tracer: Tracer, spec: CallSpec) -> BenchOutput {
    let func_idx = match profile_core::module::func_export(tracer.module(), spec.export) {
        Some(idx) => idx,
        None => {
            return BenchOutput {
                trace: tracer.trace().to_vec(),
                outcome: format!("export '{}' not found", spec.export),
            };
        }
    };

    let outcome = match tracer.call(func_idx, spec.params) {
        Ok(Outcome::Returned(Some(val))) => format!("ok (returned {val:?})"),
        Ok(Outcome::Returned(None)) => "ok".to_string(),
        Ok(Outcome::Trapped(trap)) => format!("TRAP: {trap}"),
        Err(TracerError::Trap(trap)) => format!("TRAP: {trap}"),
        Err(e) => format!("ERROR: {e}"),
    };

    BenchOutput {
        trace: tracer.trace().to_vec(),
        outcome,
    }
}
