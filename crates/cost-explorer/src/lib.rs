//! In-browser profiler: a `wasm-bindgen` wrapper around [`profile_core`].
//!
//! Exposes a JS-facing [`Tracer`] class so a page can profile an arbitrary
//! WebAssembly module. The user drives it from a small JS harness — set up
//! guest memory with [`write_private`](Tracer::write_private) /
//! [`write_public`](Tracer::write_public) / [`write_blind`](Tracer::write_blind),
//! then [`call`](Tracer::call) an export — exactly mirroring what the native
//! benches do in Rust. `call` returns the profile as a JSON string in the shape
//! the Cost Explorer consumes.

use mpz_vm_core::{Param, Write, value::Value};
use mpz_vm_ir::{Module, ValType};
use profile_core::{Outcome, render, stats, tracer::Tracer as CoreTracer};
use wasm_bindgen::prelude::*;

fn js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

fn valtype_name(ty: &ValType) -> &'static str {
    match ty {
        ValType::I32 => "i32",
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
    }
}

/// A profiler bound to one parsed WebAssembly module.
#[wasm_bindgen]
pub struct Tracer {
    inner: CoreTracer,
}

#[wasm_bindgen]
impl Tracer {
    /// Parses the WebAssembly module `bytes` and creates a profiler for it.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Tracer, JsError> {
        console_error_panic_hook::set_once();
        let module = Module::parse(bytes).map_err(js_err)?;
        let inner = CoreTracer::new(module).map_err(js_err)?;
        Ok(Tracer { inner })
    }

    /// Returns the module's exported functions as a JSON array of
    /// `{ name, func_idx, params: [type], results: [type] }`.
    pub fn exports(&self) -> String {
        let module = self.inner.module();
        let mut out = Vec::new();
        for export in module.exports() {
            let mpz_vm_ir::ExportKind::Func(idx) = export.kind else {
                continue;
            };
            let Some(func) = module.function(idx) else {
                continue;
            };
            let ty = func.func_type();
            out.push(serde_json::json!({
                "name": export.name,
                "func_idx": idx,
                "params": ty.params.iter().map(valtype_name).collect::<Vec<_>>(),
                "results": ty.results.iter().map(valtype_name).collect::<Vec<_>>(),
            }));
        }
        serde_json::Value::Array(out).to_string()
    }

    /// Returns the module's `__heap_base` (first free heap address), or 65536 if
    /// the module does not export it.
    #[wasm_bindgen(js_name = heapBase)]
    pub fn heap_base(&self) -> u32 {
        profile_core::module::heap_base(self.inner.module()).unwrap_or(65536)
    }

    /// Stages `data` at `ptr` as private (held by this party, secret to the
    /// other) — values derived from it drive private control flow.
    #[wasm_bindgen(js_name = writePrivate)]
    pub fn write_private(&mut self, ptr: u32, data: &[u8]) -> Result<(), JsError> {
        self.inner.write(ptr, Write::Private(data)).map_err(js_err)
    }

    /// Stages `data` at `ptr` as public (known to all parties).
    #[wasm_bindgen(js_name = writePublic)]
    pub fn write_public(&mut self, ptr: u32, data: &[u8]) -> Result<(), JsError> {
        self.inner.write(ptr, Write::Public(data)).map_err(js_err)
    }

    /// Reserves `len` blind bytes at `ptr` (contributed by the other party).
    #[wasm_bindgen(js_name = writeBlind)]
    pub fn write_blind(&mut self, ptr: u32, len: usize) -> Result<(), JsError> {
        self.inner.write(ptr, Write::Blind(len)).map_err(js_err)
    }

    /// Runs the exported function `export` with public scalar `args`, returning
    /// the profile as a JSON string (`{ name, stats, regions, blocks, calls }`).
    ///
    /// `args` are coerced to each parameter's WASM type; the count must match
    /// the function signature. Memory must be staged beforehand with the
    /// `write_*` methods. If the guest traps, the profile reflects execution up
    /// to the trap.
    pub fn call(&mut self, export: &str, args: Vec<f64>) -> Result<String, JsError> {
        let func_idx = profile_core::module::func_export(self.inner.module(), export)
            .ok_or_else(|| JsError::new(&format!("export '{export}' not found")))?;
        let params = build_params(self.inner.module(), func_idx, &args)?;

        let outcome = self.inner.call(func_idx, params).map_err(js_err)?;
        if let Outcome::Trapped(trap) = &outcome {
            web_sys_log(&format!("guest trapped: {trap}"));
        }

        let module = self.inner.module();
        let trace = self.inner.trace();
        let (s, regions) = stats::collect(trace);
        let blocks = stats::collect_blocks(module, trace);
        let calls = stats::collect_calls(module, trace);
        Ok(render::render_json(export, &s, &regions, &blocks, &calls))
    }
}

/// Builds public [`Param`]s for `func_idx` from JS numbers, coercing each to the
/// parameter's declared type.
fn build_params(module: &Module, func_idx: u32, args: &[f64]) -> Result<Vec<Param>, JsError> {
    let func = module
        .function(func_idx)
        .ok_or_else(|| JsError::new("function index out of range"))?;
    let params = &func.func_type().params;
    if args.len() != params.len() {
        return Err(JsError::new(&format!(
            "expected {} argument(s), got {}",
            params.len(),
            args.len()
        )));
    }
    Ok(params
        .iter()
        .zip(args)
        .map(|(ty, &a)| {
            let v = match ty {
                ValType::I32 => Value::I32(a as i32),
                ValType::I64 => Value::I64(a as i64),
                ValType::F32 => Value::F32(a as f32),
                ValType::F64 => Value::F64(a),
            };
            Param::Public(v)
        })
        .collect())
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn web_sys_log(s: &str);
}
