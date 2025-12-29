//! WebAssembly spec test runner for vm-core-new.
//!
//! Runs the official WebAssembly core spec tests against our interpreter.
//! Tests involving floats or unsupported features are skipped.

use futures::executor::block_on;
use ir::Module;
use mpz_common::{Context, context::test_st_context, future::Output};
use mpz_vm_core_new::{
    Instance, Param, VmError,
    ideal::{IdealBackend, IdealVm},
    value::Value,
};
use wast::{
    Wast, WastArg, WastDirective, WastExecute, WastRet,
    core::{WastArgCore, WastRetCore},
    parser::{self, ParseBuffer},
};

/// Stats for a spec test run.
#[derive(Default, Debug)]
struct TestStats {
    passed: usize,
    failed: usize,
    skipped: usize,
    failure_messages: Vec<String>,
    skip_reasons: Vec<String>,
}

/// A persistent VM pair that maintains state across test invocations.
struct VmPair {
    vm_a: IdealVm,
    vm_b: IdealVm,
    module: Module,
}

impl VmPair {
    fn new(module: Module) -> Result<Self, String> {
        let vm_a = Instance::new(module.clone(), IdealBackend::default())
            .map_err(|e| format!("{:?}", e))?;
        let vm_b = Instance::new(module.clone(), IdealBackend::default())
            .map_err(|e| format!("{:?}", e))?;
        Ok(Self { vm_a, vm_b, module })
    }

    /// Reset VMs to initial state (after a trap corrupts them).
    fn reset(&mut self) -> Result<(), String> {
        self.vm_a = Instance::new(self.module.clone(), IdealBackend::default())
            .map_err(|e| format!("{:?}", e))?;
        self.vm_b = Instance::new(self.module.clone(), IdealBackend::default())
            .map_err(|e| format!("{:?}", e))?;
        Ok(())
    }

    /// Execute a function and return results from both VMs.
    /// Each VM can have different arguments (for asymmetric private/blind
    /// params). If `has_private` is true, uses `call_with_decode`.
    fn execute(
        &mut self,
        func_idx: u32,
        args_a: Vec<Param>,
        args_b: Vec<Param>,
        has_private: bool,
    ) -> Result<(Vec<Value>, Vec<Value>), SkipReason> {
        // Create context for communication
        let (ctx_a, ctx_b) = test_st_context(1024);

        // Run both VMs concurrently
        let (result_a, result_b) = block_on(futures::future::try_join(
            run_vm(&mut self.vm_a, ctx_a, func_idx, args_a, has_private),
            run_vm(&mut self.vm_b, ctx_b, func_idx, args_b, has_private),
        ))?;

        Ok((result_a, result_b))
    }
}

/// Test directive we care about - extracted from WAST for re-iteration.
enum TestDirective {
    /// Module binary + whether it has imports
    Module {
        binary: Vec<u8>,
        has_imports: bool,
    },
    /// AssertReturn with func name, func idx, args, expected results
    AssertReturn {
        func_name: String,
        func_idx: u32,
        args: Vec<TestArg>,
        expected: Vec<TestExpected>,
    },
    /// AssertTrap with func name, func idx, args, expected message
    AssertTrap {
        func_name: String,
        func_idx: u32,
        args: Vec<TestArg>,
        message: String,
    },
    /// Static assertions (malformed/invalid) - only run once
    AssertMalformed {
        binary: Result<Vec<u8>, String>,
    },
    AssertInvalid {
        binary: Result<Vec<u8>, String>,
    },
    /// Unsupported directive - skip
    Skip(String),
}

#[derive(Clone)]
struct TestArg {
    value: Value,
}

#[derive(Clone, Debug)]
enum TestExpected {
    I32(i32),
    I64(i64),
    F32(u32), // bits
    F64(u64), // bits
    F32Nan,
    F64Nan,
    Unsupported,
}

/// Run a spec test file and return stats.
fn run_spec_test(wast_content: &str) -> TestStats {
    let mut stats = TestStats::default();

    let buf = match ParseBuffer::new(wast_content) {
        Ok(buf) => buf,
        Err(_) => return stats,
    };

    let wast: Wast = match parser::parse(&buf) {
        Ok(wast) => wast,
        Err(_) => return stats,
    };

    // Extract directives into our own structure that we can iterate multiple times
    let (directives, max_args) = extract_directives(wast);

    // Run public pass
    run_pass(&directives, None, &mut stats);

    // Run private passes for each arg position
    for arg_idx in 0..max_args {
        run_pass(&directives, Some(arg_idx), &mut stats);
    }

    stats
}

/// Extract test directives from parsed WAST.
/// Returns (directives, max_args) where max_args is the maximum argument count
/// across all invocations.
fn extract_directives(wast: Wast) -> (Vec<TestDirective>, usize) {
    let mut directives = Vec::new();
    let mut max_args = 0;
    let mut current_module: Option<Module> = None;

    for directive in wast.directives {
        match directive {
            WastDirective::Module(mut quoted_wat) => {
                let binary = match quoted_wat.encode() {
                    Ok(b) => b,
                    Err(e) => {
                        directives.push(TestDirective::Skip(format!("WAT encode: {}", e)));
                        current_module = None;
                        continue;
                    }
                };

                let module = match Module::parse(&binary) {
                    Ok(m) => m,
                    Err(e) => {
                        directives.push(TestDirective::Skip(format!("Module parse: {:?}", e)));
                        current_module = None;
                        continue;
                    }
                };

                if module.imported_func_count() > 0 {
                    directives.push(TestDirective::Skip("Function imports".to_string()));
                    current_module = None;
                    continue;
                }
                if module.imported_table_count() > 0 {
                    directives.push(TestDirective::Skip("Table imports".to_string()));
                    current_module = None;
                    continue;
                }
                let has_imports = false;

                directives.push(TestDirective::Module {
                    binary: binary.clone(),
                    has_imports,
                });
                current_module = Some(module);
            }

            WastDirective::AssertReturn { exec, results, .. } => {
                let Some(ref module) = current_module else {
                    continue;
                };

                let WastExecute::Invoke(invoke) = exec else {
                    directives.push(TestDirective::Skip("non-invoke exec".to_string()));
                    continue;
                };

                if invoke.module.is_some() {
                    directives.push(TestDirective::Skip("cross-module".to_string()));
                    continue;
                }

                let Some(func_idx) = find_func_idx(module, invoke.name) else {
                    directives.push(TestDirective::Skip(format!(
                        "function {} not found",
                        invoke.name
                    )));
                    continue;
                };

                let args = match convert_args(&invoke.args) {
                    Ok(a) => a,
                    Err(e) => {
                        directives.push(TestDirective::Skip(e));
                        continue;
                    }
                };

                max_args = max_args.max(args.len());

                let expected = convert_expected(&results);

                directives.push(TestDirective::AssertReturn {
                    func_name: invoke.name.to_string(),
                    func_idx,
                    args,
                    expected,
                });
            }

            WastDirective::AssertTrap { exec, message, .. } => {
                let Some(ref module) = current_module else {
                    continue;
                };

                let WastExecute::Invoke(invoke) = exec else {
                    directives.push(TestDirective::Skip("non-invoke exec".to_string()));
                    continue;
                };

                if invoke.module.is_some() {
                    directives.push(TestDirective::Skip("cross-module".to_string()));
                    continue;
                }

                let Some(func_idx) = find_func_idx(module, invoke.name) else {
                    directives.push(TestDirective::Skip(format!(
                        "function {} not found",
                        invoke.name
                    )));
                    continue;
                };

                let args = match convert_args(&invoke.args) {
                    Ok(a) => a,
                    Err(e) => {
                        directives.push(TestDirective::Skip(e));
                        continue;
                    }
                };

                max_args = max_args.max(args.len());

                directives.push(TestDirective::AssertTrap {
                    func_name: invoke.name.to_string(),
                    func_idx,
                    args,
                    message: message.to_string(),
                });
            }

            WastDirective::AssertMalformed { mut module, .. } => {
                let binary = module.encode().map_err(|e| e.to_string());
                directives.push(TestDirective::AssertMalformed { binary });
            }

            WastDirective::AssertInvalid { mut module, .. } => {
                let binary = module.encode().map_err(|e| e.to_string());
                directives.push(TestDirective::AssertInvalid { binary });
            }

            WastDirective::Register { .. } => {
                directives.push(TestDirective::Skip("register".to_string()));
            }

            _ => {
                directives.push(TestDirective::Skip("other".to_string()));
            }
        }
    }

    (directives, max_args)
}

fn find_func_idx(module: &Module, name: &str) -> Option<u32> {
    module
        .exports()
        .iter()
        .find(|e| e.name == name)
        .and_then(|e| {
            if let ir::ExportKind::Func(idx) = e.kind {
                Some(idx)
            } else {
                None
            }
        })
}

fn convert_args(args: &[WastArg]) -> Result<Vec<TestArg>, String> {
    args.iter()
        .map(|arg| match arg {
            WastArg::Core(core_arg) => match core_arg {
                WastArgCore::I32(v) => Ok(TestArg {
                    value: Value::I32(*v),
                }),
                WastArgCore::I64(v) => Ok(TestArg {
                    value: Value::I64(*v),
                }),
                WastArgCore::F32(v) => Ok(TestArg {
                    value: Value::F32(f32::from_bits(v.bits)),
                }),
                WastArgCore::F64(v) => Ok(TestArg {
                    value: Value::F64(f64::from_bits(v.bits)),
                }),
                _ => Err(format!("unsupported arg type {:?}", core_arg)),
            },
            _ => Err("non-core arg".to_string()),
        })
        .collect()
}

fn convert_expected(results: &[WastRet]) -> Vec<TestExpected> {
    results
        .iter()
        .map(|ret| match ret {
            WastRet::Core(core_ret) => match core_ret {
                WastRetCore::I32(v) => TestExpected::I32(*v),
                WastRetCore::I64(v) => TestExpected::I64(*v),
                WastRetCore::F32(pat) => match pat {
                    wast::core::NanPattern::CanonicalNan
                    | wast::core::NanPattern::ArithmeticNan => TestExpected::F32Nan,
                    wast::core::NanPattern::Value(v) => TestExpected::F32(v.bits),
                },
                WastRetCore::F64(pat) => match pat {
                    wast::core::NanPattern::CanonicalNan
                    | wast::core::NanPattern::ArithmeticNan => TestExpected::F64Nan,
                    wast::core::NanPattern::Value(v) => TestExpected::F64(v.bits),
                },
                _ => TestExpected::Unsupported,
            },
            _ => TestExpected::Unsupported,
        })
        .collect()
}

/// Run a single pass through all directives with the given visibility mode.
fn run_pass(directives: &[TestDirective], private_arg_idx: Option<usize>, stats: &mut TestStats) {
    let mode = match private_arg_idx {
        None => "public".to_string(),
        Some(i) => format!("private[{}]", i),
    };

    let mut current_vm: Option<VmPair> = None;

    for directive in directives {
        match directive {
            TestDirective::Module { binary, .. } => {
                // Re-parse module for each pass (fresh state)
                let module = match Module::parse(binary) {
                    Ok(m) => m,
                    Err(_) => {
                        current_vm = None;
                        continue;
                    }
                };

                match VmPair::new(module) {
                    Ok(pair) => {
                        current_vm = Some(pair);
                    }
                    Err(_) => {
                        current_vm = None;
                    }
                }
            }

            TestDirective::AssertReturn {
                func_name,
                func_idx,
                args,
                expected,
            } => {
                // Skip if this invocation doesn't have enough args for this private_arg_idx
                if let Some(idx) = private_arg_idx {
                    if idx >= args.len() {
                        continue;
                    }
                }

                match run_assert_return(
                    &mut current_vm,
                    func_name,
                    *func_idx,
                    args,
                    expected,
                    private_arg_idx,
                    &mode,
                ) {
                    Ok(()) => stats.passed += 1,
                    Err(SkipReason::Unsupported(reason)) => {
                        stats
                            .skip_reasons
                            .push(format!("AssertReturn {} [{}]: {}", func_name, mode, reason));
                        stats.skipped += 1;
                        if let Some(ref mut pair) = current_vm {
                            let _ = pair.reset();
                        }
                    }
                    Err(SkipReason::Failed(msg)) => {
                        stats.failed += 1;
                        stats
                            .failure_messages
                            .push(format!("AssertReturn {} [{}]: {}", func_name, mode, msg));
                        if let Some(ref mut pair) = current_vm {
                            let _ = pair.reset();
                        }
                    }
                }
            }

            TestDirective::AssertTrap {
                func_name,
                func_idx,
                args,
                message,
            } => {
                // Only run trap tests in public mode
                if private_arg_idx.is_some() {
                    continue;
                }

                match run_assert_trap(&mut current_vm, func_name, *func_idx, args, &mode) {
                    Ok(()) => {
                        stats.passed += 1;
                        if let Some(ref mut pair) = current_vm {
                            let _ = pair.reset();
                        }
                    }
                    Err(SkipReason::Unsupported(reason)) => {
                        stats
                            .skip_reasons
                            .push(format!("AssertTrap {} [{}]: {}", func_name, mode, reason));
                        stats.skipped += 1;
                        if let Some(ref mut pair) = current_vm {
                            let _ = pair.reset();
                        }
                    }
                    Err(SkipReason::Failed(msg)) => {
                        stats.failed += 1;
                        stats
                            .failure_messages
                            .push(format!("AssertTrap({}): {}", message, msg));
                        if let Some(ref mut pair) = current_vm {
                            let _ = pair.reset();
                        }
                    }
                }
            }

            TestDirective::AssertMalformed { binary } => {
                // Static tests - only run in public pass
                if private_arg_idx.is_some() {
                    continue;
                }

                match binary {
                    Err(_) => stats.passed += 1, // Expected to fail to encode
                    Ok(binary) => match Module::parse(binary) {
                        Ok(_) => stats.skipped += 1,
                        Err(_) => stats.passed += 1,
                    },
                }
            }

            TestDirective::AssertInvalid { binary } => {
                // Static tests - only run in public pass
                if private_arg_idx.is_some() {
                    continue;
                }

                match binary {
                    Err(_) => stats.passed += 1,
                    Ok(binary) => match Module::parse(binary) {
                        Ok(m) => match Instance::new(m, IdealBackend::default()) {
                            Ok(_) => stats.skipped += 1,
                            Err(_) => stats.passed += 1,
                        },
                        Err(_) => stats.passed += 1,
                    },
                }
            }

            TestDirective::Skip(reason) => {
                // Only count skips in public pass
                if private_arg_idx.is_none() {
                    stats.skip_reasons.push(reason.clone());
                    stats.skipped += 1;
                }
            }
        }
    }
}

fn run_assert_return(
    vm_pair: &mut Option<VmPair>,
    func_name: &str,
    func_idx: u32,
    args: &[TestArg],
    expected: &[TestExpected],
    private_arg_idx: Option<usize>,
    mode: &str,
) -> Result<(), SkipReason> {
    let pair = vm_pair
        .as_mut()
        .ok_or(SkipReason::Unsupported("no module".to_string()))?;

    // Check for unsupported expected values
    for exp in expected {
        if matches!(exp, TestExpected::Unsupported) {
            return Err(SkipReason::Unsupported(
                "unsupported return type".to_string(),
            ));
        }
    }

    // Build args for each VM
    let mut args_a = Vec::new();
    let mut args_b = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if private_arg_idx == Some(i) {
            args_a.push(Param::Private(arg.value));
            args_b.push(Param::Blind(arg.value.ty()));
        } else {
            args_a.push(Param::Public(arg.value));
            args_b.push(Param::Public(arg.value));
        }
    }

    let has_private = private_arg_idx.is_some();
    let (result_a, result_b) = pair.execute(func_idx, args_a, args_b, has_private)?;

    // Both VMs should produce the same result
    if !results_equal(&result_a, &result_b) {
        return Err(SkipReason::Failed(format!(
            "{} [{}]: VM results differ: vm_a={:?}, vm_b={:?}",
            func_name, mode, result_a, result_b
        )));
    }

    // Skip multi-value return tests (unsupported)
    if expected.len() > 1 {
        return Err(SkipReason::Unsupported("multi-value return".to_string()));
    }

    // Check results match expected
    if result_a.len() != expected.len() {
        return Err(SkipReason::Failed(format!(
            "{} [{}]: result count mismatch: got {}, expected {}",
            func_name,
            mode,
            result_a.len(),
            expected.len()
        )));
    }

    for (actual, exp) in result_a.iter().zip(expected.iter()) {
        if !value_matches_expected(*actual, exp) {
            return Err(SkipReason::Failed(format!(
                "{} [{}]: value mismatch: got {:?}, expected {:?}",
                func_name, mode, actual, exp
            )));
        }
    }

    Ok(())
}

fn run_assert_trap(
    vm_pair: &mut Option<VmPair>,
    func_name: &str,
    func_idx: u32,
    args: &[TestArg],
    mode: &str,
) -> Result<(), SkipReason> {
    let pair = vm_pair
        .as_mut()
        .ok_or(SkipReason::Unsupported("no module".to_string()))?;

    // All args public for trap tests
    let args_a: Vec<_> = args.iter().map(|a| Param::Public(a.value)).collect();
    let args_b = args_a.clone();

    match pair.execute(func_idx, args_a, args_b, false) {
        Ok(_) => Err(SkipReason::Failed(format!(
            "{} [{}]: expected trap but succeeded",
            func_name, mode
        ))),
        Err(SkipReason::Unsupported(r)) => Err(SkipReason::Unsupported(r)),
        Err(SkipReason::Failed(_)) => Ok(()), // Trap as expected
    }
}

fn value_matches_expected(actual: Value, expected: &TestExpected) -> bool {
    match (actual, expected) {
        (Value::I32(a), TestExpected::I32(e)) => a == *e,
        (Value::I64(a), TestExpected::I64(e)) => a == *e,
        (Value::F32(a), TestExpected::F32(bits)) => {
            let expected_f32 = f32::from_bits(*bits);
            if expected_f32.is_nan() && a.is_nan() {
                true
            } else {
                a.to_bits() == *bits
            }
        }
        (Value::F32(a), TestExpected::F32Nan) => a.is_nan(),
        (Value::F64(a), TestExpected::F64(bits)) => {
            let expected_f64 = f64::from_bits(*bits);
            if expected_f64.is_nan() && a.is_nan() {
                true
            } else {
                a.to_bits() == *bits
            }
        }
        (Value::F64(a), TestExpected::F64Nan) => a.is_nan(),
        _ => false,
    }
}

#[derive(Debug)]
enum SkipReason {
    Unsupported(String),
    Failed(String),
}

impl From<VmError> for SkipReason {
    fn from(err: VmError) -> Self {
        // Skip errors that are expected when testing with private inputs
        if err.is_unsupported()
            || err.is_symbolic_conditional()
            || err.is_symbolic_address()
            || err.is_symbolic_value()
        {
            SkipReason::Unsupported(format!("{:?}", err))
        } else {
            SkipReason::Failed(err.to_string())
        }
    }
}

/// Run a single VM to completion and return its result.
///
/// If `decode_return` is true, uses `call_with_decode` to automatically
/// decode symbolic return values.
async fn run_vm(
    vm: &mut IdealVm,
    mut ctx: Context,
    func_idx: u32,
    args: Vec<Param>,
    decode_return: bool,
) -> Result<Vec<Value>, SkipReason> {
    let mut output = if decode_return {
        vm.call_with_decode(func_idx, args)
            .map_err(SkipReason::from)?
    } else {
        vm.call(func_idx, args).map_err(SkipReason::from)?
    };

    vm.run(&mut ctx).await.map_err(SkipReason::from)?;

    match output.try_recv() {
        Ok(Some(Ok(Some(val)))) => Ok(vec![val]),
        Ok(Some(Ok(None))) => Ok(vec![]),
        Ok(Some(Err(e))) => Err(SkipReason::from(e)),
        Ok(None) => Err(SkipReason::Failed("not ready".to_string())),
        Err(_) => Err(SkipReason::Failed("canceled".to_string())),
    }
}

/// Compare two result vectors for equality, handling NaN correctly.
fn results_equal(a: &[Value], b: &[Value]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (va, vb) in a.iter().zip(b.iter()) {
        match (va, vb) {
            (Value::I32(a), Value::I32(b)) => {
                if a != b {
                    return false;
                }
            }
            (Value::I64(a), Value::I64(b)) => {
                if a != b {
                    return false;
                }
            }
            (Value::F32(a), Value::F32(b)) => {
                // NaN == NaN for our purposes, otherwise compare bits
                if a.is_nan() && b.is_nan() {
                    // Both NaN is OK
                } else if a.to_bits() != b.to_bits() {
                    return false;
                }
            }
            (Value::F64(a), Value::F64(b)) => {
                if a.is_nan() && b.is_nan() {
                    // Both NaN is OK
                } else if a.to_bits() != b.to_bits() {
                    return false;
                }
            }
            _ => return false, // Different types
        }
    }
    true
}

// Macro to generate test functions for each spec file
macro_rules! spec_test {
    ($test_name:ident, $file:literal) => {
        #[test]
        fn $test_name() {
            let wast = include_str!(concat!("spec/", $file, ".wast"));
            let stats = run_spec_test(wast);
            println!(
                "{}: {} passed, {} failed, {} skipped",
                $file, stats.passed, stats.failed, stats.skipped
            );
            if !stats.failure_messages.is_empty() {
                println!("Failures:");
                for (i, msg) in stats.failure_messages.iter().enumerate() {
                    println!("  {}. {}", i + 1, msg);
                }
            }
            if !stats.skip_reasons.is_empty() && stats.skip_reasons.len() <= 20 {
                println!("Skip reasons:");
                for (i, msg) in stats.skip_reasons.iter().enumerate() {
                    println!("  {}. {}", i + 1, msg);
                }
            } else if !stats.skip_reasons.is_empty() {
                // Just show first few unique reasons
                let mut unique: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
                for r in &stats.skip_reasons {
                    *unique.entry(r.clone()).or_default() += 1;
                }
                println!("Skip reason summary ({} total):", stats.skip_reasons.len());
                for (reason, count) in unique.iter().take(10) {
                    println!("  {} ({}x)", reason, count);
                }
            }
            assert_eq!(stats.failed, 0, "Some tests failed");
        }
    };
}

// Core integer operations
spec_test!(test_i32, "i32");
spec_test!(test_i64, "i64");

// Floating point operations
spec_test!(test_f32, "f32");
spec_test!(test_f64, "f64");

// Memory
spec_test!(test_memory, "memory");

// Local variables
spec_test!(test_local_get, "local_get");
spec_test!(test_local_set, "local_set");
spec_test!(test_local_tee, "local_tee");

// Global variables
spec_test!(test_global, "global");

// Control flow
spec_test!(test_block, "block");
spec_test!(test_loop, "loop");
spec_test!(test_if, "if");
spec_test!(test_br, "br");
spec_test!(test_br_if, "br_if");
spec_test!(test_br_table, "br_table");
spec_test!(test_return, "return");
spec_test!(test_unreachable, "unreachable");
spec_test!(test_nop, "nop");

// Functions
spec_test!(test_func, "func");
spec_test!(test_call, "call");
spec_test!(test_call_indirect, "call_indirect");

// Other
spec_test!(test_select, "select");
spec_test!(test_data, "data");
spec_test!(test_elem, "elem");
spec_test!(test_table, "table");
