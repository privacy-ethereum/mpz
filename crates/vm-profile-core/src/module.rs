//! Small read-only helpers over a parsed [`Module`].

use mpz_vm_ir::{ConstExpr, ExportKind, Module};

/// Returns the value of the module's `__heap_base` global — the first address
/// above static data where the guest heap begins — if the module exports it.
pub fn heap_base(module: &Module) -> Option<u32> {
    for export in module.exports() {
        if export.name == "__heap_base"
            && let ExportKind::Global(idx) = export.kind
            && let ConstExpr::I32(val) = module.globals()[idx as usize].init
        {
            return Some(val as u32);
        }
    }
    None
}

/// Resolves an exported function by name to its function index.
pub fn func_export(module: &Module, name: &str) -> Option<u32> {
    module.exports().iter().find_map(|e| match e.kind {
        ExportKind::Func(idx) if e.name == name => Some(idx),
        _ => None,
    })
}
