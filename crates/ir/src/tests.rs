use crate::{Function, Module, ValType};

fn load_fixture(name: &str) -> Vec<u8> {
    let wat_path = format!("tests/fixtures/{}.wat", name);
    let wat = std::fs::read_to_string(&wat_path)
        .unwrap_or_else(|_| panic!("Failed to read fixture: {}", wat_path));
    wat::parse_str(&wat).unwrap_or_else(|_| panic!("Failed to parse WAT: {}", wat_path))
}

#[test]
fn test_parse_simple_module() {
    let wasm = load_fixture("empty");
    let module = Module::parse(&wasm).unwrap();

    assert!(module.types().is_empty());
    assert!(module.functions().is_empty());
    assert!(module.exports().is_empty());
}

#[test]
fn test_parse_module_with_function() {
    let wasm = load_fixture("simple_function");
    let module = Module::parse(&wasm).unwrap();

    assert_eq!(module.types().len(), 1);
    assert_eq!(module.types()[0].params.len(), 0);
    assert_eq!(module.types()[0].results.len(), 1);
    assert_eq!(module.types()[0].results[0], ValType::I32);
    assert_eq!(module.functions().len(), 1);
    // Function is local, check func_type matches type[0]
    let func = &module.functions()[0];
    assert_eq!(func.func_type().results[0], ValType::I32);
}

#[test]
fn test_parse_module_with_import() {
    let wasm = load_fixture("import");
    let module = Module::parse(&wasm).unwrap();

    assert_eq!(module.types().len(), 1);
    // Imported function is now in functions list
    assert_eq!(module.imported_func_count(), 1);
    let func = &module.functions()[0];
    assert!(matches!(func, Function::Import(_)));
    let import = func.as_import().unwrap();
    assert_eq!(import.module(), "env");
    assert_eq!(import.name(), "log");
}

#[test]
fn test_parse_module_with_export() {
    let wasm = load_fixture("export");
    let module = Module::parse(&wasm).unwrap();

    assert_eq!(module.exports().len(), 1);
    assert_eq!(module.exports()[0].name, "add");
}

#[test]
fn test_parse_module_with_memory() {
    let wasm = load_fixture("memory");
    let module = Module::parse(&wasm).unwrap();

    assert_eq!(module.memories().len(), 1);
    assert_eq!(module.memories()[0].ty.limits.min, 1);
    assert_eq!(module.data().len(), 1);
    assert_eq!(module.data()[0].data, b"Hello, World!");
}

#[test]
fn test_parse_module_with_table() {
    let wasm = load_fixture("table");
    let module = Module::parse(&wasm).unwrap();

    assert_eq!(module.tables().len(), 1);
    assert_eq!(module.tables()[0].ty.limits.min, 2);
    assert_eq!(module.functions().len(), 2);
    assert_eq!(module.elements().len(), 1);
}

#[test]
fn test_parse_module_with_globals() {
    let wasm = load_fixture("global");
    let module = Module::parse(&wasm).unwrap();

    assert_eq!(module.globals().len(), 2);
    assert!(!module.globals()[0].ty.mutable);
    assert!(module.globals()[1].ty.mutable);
    assert_eq!(module.exports().len(), 3);
}

#[test]
fn test_parse_module_with_control_flow() {
    let wasm = load_fixture("control_flow");
    let module = Module::parse(&wasm).unwrap();

    assert_eq!(module.functions().len(), 1);
    assert_eq!(module.exports().len(), 1);
    assert_eq!(module.exports()[0].name, "factorial");

    // Verify the function has locals and a non-trivial body
    let func = module.functions()[0].as_local().unwrap();
    assert!(!func.locals().is_empty());
    assert!(func.body().len() > 10);
}

#[test]
fn test_parse_float_types() {
    // Float types are now parsed (but will trap at runtime if executed)
    let wasm = load_fixture("reject_float");
    let module = Module::parse(&wasm).unwrap();

    assert_eq!(module.functions().len(), 1);
    let func = module.functions()[0].as_local().unwrap();
    // Verify it has f32 param and result
    assert_eq!(func.func_type().params.len(), 1);
    assert_eq!(func.func_type().params[0], ValType::F32);
    assert_eq!(func.func_type().results.len(), 1);
    assert_eq!(func.func_type().results[0], ValType::F32);
}
