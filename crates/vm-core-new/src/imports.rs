use ir::{FuncType, Function, Module, ValType};

use crate::VmError;

pub(crate) fn validate_imports(module: &Module) -> Result<(), VmError> {
    for func in module.functions() {
        if let Function::Import(import) = func {
            let expected_sig = match (import.module(), import.name()) {
                // === WASI imports ===
                ("wasi_snapshot_preview1", "fd_write") => FuncType {
                    params: vec![ValType::I32; 4],
                    results: vec![ValType::I32],
                },
                ("wasi_snapshot_preview1", "environ_sizes_get") => FuncType {
                    params: vec![ValType::I32; 2],
                    results: vec![ValType::I32],
                },
                ("wasi_snapshot_preview1", "environ_get") => FuncType {
                    params: vec![ValType::I32; 2],
                    results: vec![ValType::I32],
                },
                ("wasi_snapshot_preview1", "proc_exit") => FuncType {
                    params: vec![ValType::I32],
                    results: vec![],
                },
                // === MPZ imports ===
                // Memory decodes
                ("mpz", "decode") => FuncType {
                    params: vec![ValType::I32, ValType::I32],
                    results: vec![ValType::I32],
                },
                ("mpz", "decode_wait") => FuncType {
                    params: vec![ValType::I32],
                    results: vec![],
                },
                // Memory allocation tracking
                ("mpz", "alloc") => FuncType {
                    params: vec![ValType::I32, ValType::I32],
                    results: vec![],
                },
                ("mpz", "free") => FuncType {
                    params: vec![ValType::I32, ValType::I32],
                    results: vec![],
                },
                // Preprocessing lifecycle
                ("mpz", "preprocess_enter") => FuncType {
                    params: vec![],
                    results: vec![],
                },
                ("mpz", "preprocess_exit") => FuncType {
                    params: vec![],
                    results: vec![ValType::I32],
                },
                // Symbolic value creation
                ("mpz", "symbolic") => FuncType {
                    params: vec![ValType::I32, ValType::I32],
                    results: vec![],
                },
                // Execute preprocessed function
                ("mpz", "call_enter") => FuncType {
                    params: vec![ValType::I32],
                    results: vec![],
                },
                ("mpz", "call_arg") => FuncType {
                    params: vec![ValType::I32, ValType::I32],
                    results: vec![],
                },
                ("mpz", "call_result_size") => FuncType {
                    params: vec![],
                    results: vec![ValType::I32],
                },
                ("mpz", "call_exit") => FuncType {
                    params: vec![ValType::I32, ValType::I32],
                    results: vec![],
                },
                _ => {
                    return Err(VmError::UnsupportedImport {
                        module: import.module().to_string(),
                        name: import.name().to_string(),
                    });
                }
            };

            if import.func_type() != &expected_sig {
                return Err(VmError::ImportSignatureMismatch {
                    name: import.name().to_string(),
                });
            }
        }
    }
    Ok(())
}
