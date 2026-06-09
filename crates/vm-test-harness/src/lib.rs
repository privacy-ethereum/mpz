//! Shared WebAssembly spec-conformance test harness.
//!
//! Runs the official WebAssembly core spec tests (`*.wast`) against any
//! implementation that can instantiate a [`Module`] as a two-party pair and run
//! a function on both parties. The pluggable surface is the [`SpecVm`] trait,
//! which also classifies which of its errors count as an expected "unsupported"
//! skip rather than a failure; [`SpecConfig`] tunes which passes run.
//!
//! The bundled `.wast` suites are exposed by [`suites`]. Use the
//! [`wasm_spec_tests!`] macro to generate one `#[test]` per suite for an
//! implementation:
//!
//! ```ignore
//! struct MyPair { /* ... */ }
//! impl mpz_vm_test_harness::SpecVm for MyPair { /* ... */ }
//! mpz_vm_test_harness::wasm_spec_tests!(MyPair, mpz_vm_test_harness::SpecConfig::default());
//! ```

use mpz_vm_ir::Module;
use mpz_vm_core::{Param, value::Value};
use wast::{
    Wast, WastArg, WastDirective, WastExecute, WastRet,
    core::{WastArgCore, WastRetCore},
    parser::{self, ParseBuffer},
};

pub mod behavior;
pub mod suites;

/// A two-party implementation under test.
///
/// Party A holds private inputs as [`Param::Private`]; party B sees them as
/// [`Param::Blind`]. Both parties must agree on the result (or both trap/error).
pub trait SpecVm: Sized {
    /// The error type reported by a run.
    type Error: core::error::Error;

    /// Labels of the configurations this implementation wants exercised. Every
    /// suite is run once per variant, so the same conformance corpus stresses
    /// each one. Most implementations keep the single default; an implementation
    /// with tunable internals (e.g. proof chunking) can return several to drive
    /// the whole spec through each configuration.
    ///
    /// The strings are opaque to the harness and passed back to
    /// [`instantiate`](Self::instantiate).
    fn variants() -> Vec<String> {
        vec![String::new()]
    }

    /// Construct a fresh party pair for `module` under the named `variant` (one
    /// of the strings returned by [`variants`](Self::variants)). Called once per
    /// `(module)` directive and again whenever the harness resets after a trap
    /// or failure. `Err` carries a human-readable reason recorded as a skip.
    fn instantiate(module: &Module, variant: &str) -> Result<Self, String>;

    /// Run `func_idx` on both parties with the given per-party params, returning
    /// each party's optional return value. An `Err` from either party is
    /// surfaced as a single [`Self::Error`] (the harness then classifies it via
    /// [`Self::is_expected_unsupported`]).
    fn run(
        &mut self,
        func_idx: u32,
        params_a: Vec<Param>,
        params_b: Vec<Param>,
    ) -> Result<(Option<Value>, Option<Value>), Self::Error>;

    /// Classify an error: `true` => an expected/unsupported condition, counted
    /// as a skip; `false` => a real failure.
    fn is_expected_unsupported(err: &Self::Error) -> bool;
}

/// The privacy pattern applied to a function's arguments in one pass: which
/// argument positions party A holds privately (party B sees them blind), the
/// rest public to both.
#[derive(Clone, Copy)]
enum Privacy {
    /// Every argument public to both parties.
    AllPublic,
    /// Only the argument at this index is private.
    One(usize),
    /// Every argument is private.
    AllPrivate,
    /// Even-indexed arguments private, odd-indexed public — interleaves private
    /// and public params to exercise register/commit alignment across a skipped
    /// public slot.
    Alternating,
}

impl Privacy {
    /// Whether the argument at `i` is private under this pattern.
    fn is_private(self, i: usize) -> bool {
        match self {
            Privacy::AllPublic => false,
            Privacy::One(idx) => i == idx,
            Privacy::AllPrivate => true,
            Privacy::Alternating => i % 2 == 0,
        }
    }

    /// Whether this pattern is worth running on an invocation with `n_args`
    /// arguments. Patterns that would degenerate into one already covered by
    /// another pass (or by the all-public pass) are skipped, so the extra passes
    /// only do real work on invocations they actually distinguish.
    fn runs_invocation(self, n_args: usize) -> bool {
        match self {
            Privacy::AllPublic => true,
            Privacy::One(i) => i < n_args,
            // With <2 args this is `One(0)` or all-public.
            Privacy::AllPrivate => n_args >= 2,
            // Needs a public between two privates to differ from `One(0)`.
            Privacy::Alternating => n_args >= 3,
        }
    }

    fn label(self) -> String {
        match self {
            Privacy::AllPublic => "public".to_string(),
            Privacy::One(i) => format!("private[{i}]"),
            Privacy::AllPrivate => "all-private".to_string(),
            Privacy::Alternating => "alternating".to_string(),
        }
    }
}

/// Build the privacy passes for a suite whose largest invocation takes
/// `max_args` arguments.
fn privacy_passes(config: &SpecConfig, max_args: usize) -> Vec<Privacy> {
    let mut passes = vec![Privacy::AllPublic];
    if config.run_private_passes {
        for i in 0..max_args {
            passes.push(Privacy::One(i));
        }
        if max_args >= 2 {
            passes.push(Privacy::AllPrivate);
        }
        if max_args >= 3 {
            passes.push(Privacy::Alternating);
        }
    }
    passes
}

/// Tuning for a spec run.
pub struct SpecConfig {
    /// Run the private-input passes (each argument position made private in
    /// turn). When `false`, only the all-public pass runs.
    pub run_private_passes: bool,
}

impl Default for SpecConfig {
    fn default() -> Self {
        Self {
            run_private_passes: true,
        }
    }
}

/// Stats for a single suite run.
#[derive(Default, Debug)]
pub struct SuiteStats {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub failure_messages: Vec<String>,
    pub skip_reasons: Vec<String>,
}

impl SuiteStats {
    /// The skip reasons bucketed into coarse, stable categories and counted,
    /// sorted by descending count (ties broken by category name). Lets callers
    /// present *why* a suite skipped without re-parsing the raw reasons.
    pub fn skip_summary(&self) -> Vec<(&'static str, usize)> {
        let mut counts: std::collections::BTreeMap<&'static str, usize> =
            std::collections::BTreeMap::new();
        for reason in &self.skip_reasons {
            *counts.entry(skip_category(reason)).or_insert(0) += 1;
        }
        let mut out: Vec<(&'static str, usize)> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        out
    }
}

/// Bucket a skip-reason string into a coarse category. Best-effort: matches the
/// harness-generated reasons and common implementation-error shapes.
fn skip_category(reason: &str) -> &'static str {
    if reason.contains("float") {
        "float input/op"
    } else if reason.contains("private branching") {
        "private control flow"
    } else if reason.contains("op not yet supported") {
        "unsupported op"
    } else if reason.contains("SymbolicValue") {
        "symbolic value"
    } else if reason.contains("SymbolicAddress") {
        "symbolic address"
    } else if reason.contains("multi-value") {
        "multi-value return"
    } else if reason.contains("import") {
        "imports"
    } else if reason.contains("Module parse") || reason.contains("WAT encode") {
        "module parse"
    } else if reason.contains("unsupported return type")
        || reason.contains("unsupported arg type")
        || reason.contains("non-core")
    {
        "unsupported value type"
    } else if reason.contains("non-invoke") {
        "non-invoke directive"
    } else if reason.contains("cross-module") {
        "cross-module"
    } else if reason.contains("register") {
        "register directive"
    } else if reason.contains("no module") {
        "no module"
    } else if reason.contains("not found") {
        "function not found"
    } else if reason.contains("static assertion") {
        "static assertion (malformed/invalid)"
    } else {
        "other"
    }
}

/// Run one `.wast` suite against `V` and return its stats.
pub fn run_suite<V: SpecVm>(wast_content: &str, config: &SpecConfig) -> SuiteStats {
    let mut stats = SuiteStats::default();

    let buf = match ParseBuffer::new(wast_content) {
        Ok(buf) => buf,
        Err(_) => return stats,
    };
    let wast: Wast = match parser::parse(&buf) {
        Ok(wast) => wast,
        Err(_) => return stats,
    };

    let (directives, max_args) = extract_directives(wast);
    let passes = privacy_passes(config, max_args);

    for variant in V::variants() {
        for &privacy in &passes {
            run_pass::<V>(&directives, privacy, &variant, &mut stats);
        }
    }

    stats
}

/// Test directive we care about - extracted from WAST for re-iteration.
enum TestDirective {
    Module {
        binary: Vec<u8>,
    },
    AssertReturn {
        func_name: String,
        func_idx: u32,
        args: Vec<TestArg>,
        expected: Vec<TestExpected>,
    },
    AssertTrap {
        func_idx: u32,
        args: Vec<TestArg>,
        message: String,
    },
    AssertMalformed {
        binary: Result<Vec<u8>, String>,
    },
    AssertInvalid {
        binary: Result<Vec<u8>, String>,
    },
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
    F32(u32),
    F64(u64),
    F32Nan,
    F64Nan,
    Unsupported,
}

/// Extract test directives from parsed WAST.
/// Returns `(directives, max_args)` where `max_args` is the maximum argument
/// count across all invocations.
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
                directives.push(TestDirective::Module {
                    binary: binary.clone(),
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
            if let mpz_vm_ir::ExportKind::Func(idx) = e.kind {
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

/// Run a single pass through all directives with the given privacy pattern and
/// implementation variant.
fn run_pass<V: SpecVm>(
    directives: &[TestDirective],
    privacy: Privacy,
    variant: &str,
    stats: &mut SuiteStats,
) {
    let mode = privacy.label();
    // The static-assertion and skip-accounting directives are independent of the
    // privacy pattern, so they are tallied only on the all-public pass to avoid
    // multiplying their counts across passes and variants.
    let primary_pass = matches!(privacy, Privacy::AllPublic) && variant.is_empty();

    let mut current_module: Option<Module> = None;
    let mut current_vm: Option<V> = None;

    for directive in directives {
        match directive {
            TestDirective::Module { binary, .. } => match Module::parse(binary) {
                Ok(module) => match V::instantiate(&module, variant) {
                    Ok(vm) => {
                        current_module = Some(module);
                        current_vm = Some(vm);
                    }
                    Err(_) => {
                        current_module = None;
                        current_vm = None;
                    }
                },
                Err(_) => {
                    current_module = None;
                    current_vm = None;
                }
            },

            TestDirective::AssertReturn {
                func_name,
                func_idx,
                args,
                expected,
            } => {
                if !privacy.runs_invocation(args.len()) {
                    continue;
                }

                let result = run_assert_return::<V>(
                    &mut current_vm,
                    func_name,
                    *func_idx,
                    args,
                    expected,
                    privacy,
                    &mode,
                );
                record(
                    result,
                    stats,
                    &mut current_vm,
                    current_module.as_ref(),
                    variant,
                    &format!("AssertReturn {} [{}]", func_name, mode),
                    // A passing AssertReturn leaves valid persistent state
                    // (memory/globals) that later directives may rely on.
                    false,
                );
            }

            TestDirective::AssertTrap {
                func_idx,
                args,
                message,
                ..
            } => {
                // A trap is a public outcome: it must hold whether the
                // trap-determining operand is public or private, so run it under
                // every privacy pattern (this exercises trapping on committed
                // values, not just public ones).
                if !privacy.runs_invocation(args.len()) {
                    continue;
                }

                let result = run_assert_trap::<V>(&mut current_vm, *func_idx, args, privacy);
                record(
                    result,
                    stats,
                    &mut current_vm,
                    current_module.as_ref(),
                    variant,
                    &format!("AssertTrap({}) [{}]", message, mode),
                    // A trap leaves the VM terminal; reset for the next directive.
                    true,
                );
            }

            TestDirective::AssertMalformed { binary } => {
                if !primary_pass {
                    continue;
                }
                match binary {
                    Err(_) => stats.passed += 1,
                    Ok(binary) => match Module::parse(binary) {
                        Ok(_) => {
                            stats.skipped += 1;
                            stats.skip_reasons.push("static assertion".to_string());
                        }
                        Err(_) => stats.passed += 1,
                    },
                }
            }

            TestDirective::AssertInvalid { binary } => {
                if !primary_pass {
                    continue;
                }
                match binary {
                    Err(_) => stats.passed += 1,
                    Ok(binary) => match Module::parse(binary) {
                        Ok(m) => match V::instantiate(&m, variant) {
                            Ok(_) => {
                                stats.skipped += 1;
                                stats.skip_reasons.push("static assertion".to_string());
                            }
                            Err(_) => stats.passed += 1,
                        },
                        Err(_) => stats.passed += 1,
                    },
                }
            }

            TestDirective::Skip(reason) => {
                if primary_pass {
                    stats.skip_reasons.push(reason.clone());
                    stats.skipped += 1;
                }
            }
        }
    }
}

/// Fold a single assertion's outcome into `stats`, resetting the VM pair on
/// anything other than a clean pass.
fn record<V: SpecVm>(
    result: Result<(), SkipReason>,
    stats: &mut SuiteStats,
    current_vm: &mut Option<V>,
    current_module: Option<&Module>,
    variant: &str,
    context: &str,
    reset_on_success: bool,
) {
    match result {
        Ok(()) => {
            stats.passed += 1;
            if reset_on_success {
                reset(current_vm, current_module, variant);
            }
        }
        Err(SkipReason::Unsupported(reason)) => {
            stats.skipped += 1;
            stats.skip_reasons.push(format!("{}: {}", context, reason));
            reset(current_vm, current_module, variant);
        }
        Err(SkipReason::Failed(msg)) => {
            stats.failed += 1;
            stats.failure_messages.push(format!("{}: {}", context, msg));
            reset(current_vm, current_module, variant);
        }
    }
}

fn reset<V: SpecVm>(current_vm: &mut Option<V>, current_module: Option<&Module>, variant: &str) {
    if let Some(module) = current_module {
        *current_vm = V::instantiate(module, variant).ok();
    }
}

#[allow(clippy::too_many_arguments)]
fn run_assert_return<V: SpecVm>(
    vm: &mut Option<V>,
    func_name: &str,
    func_idx: u32,
    args: &[TestArg],
    expected: &[TestExpected],
    privacy: Privacy,
    mode: &str,
) -> Result<(), SkipReason> {
    let vm = vm
        .as_mut()
        .ok_or(SkipReason::Unsupported("no module".to_string()))?;

    for exp in expected {
        if matches!(exp, TestExpected::Unsupported) {
            return Err(SkipReason::Unsupported(
                "unsupported return type".to_string(),
            ));
        }
    }

    let (args_a, args_b) = split_args(args, privacy);

    let (result_a, result_b) = vm
        .run(func_idx, args_a, args_b)
        .map_err(|e| classify::<V>(e))?;
    let result_a = to_vec(result_a);
    let result_b = to_vec(result_b);

    if !results_equal(&result_a, &result_b) {
        return Err(SkipReason::Failed(format!(
            "{} [{}]: party results differ: a={:?}, b={:?}",
            func_name, mode, result_a, result_b
        )));
    }

    if expected.len() > 1 {
        return Err(SkipReason::Unsupported("multi-value return".to_string()));
    }

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

fn run_assert_trap<V: SpecVm>(
    vm: &mut Option<V>,
    func_idx: u32,
    args: &[TestArg],
    privacy: Privacy,
) -> Result<(), SkipReason> {
    let vm = vm
        .as_mut()
        .ok_or(SkipReason::Unsupported("no module".to_string()))?;

    let (args_a, args_b) = split_args(args, privacy);

    match vm.run(func_idx, args_a, args_b) {
        Ok(_) => Err(SkipReason::Failed("expected trap but succeeded".to_string())),
        Err(e) => match classify::<V>(e) {
            // An expected/unsupported error is still a skip, not a satisfied
            // trap.
            SkipReason::Unsupported(r) => Err(SkipReason::Unsupported(r)),
            // Any other error is the trap we expected.
            SkipReason::Failed(_) => Ok(()),
        },
    }
}

/// Split arguments into per-party params under a privacy pattern. A private
/// argument is held by party A (`Param::Private`) and seen blind by party B
/// (`Param::Blind`); a public argument is held concretely by both.
fn split_args(args: &[TestArg], privacy: Privacy) -> (Vec<Param>, Vec<Param>) {
    let mut args_a = Vec::with_capacity(args.len());
    let mut args_b = Vec::with_capacity(args.len());
    for (i, arg) in args.iter().enumerate() {
        if privacy.is_private(i) {
            args_a.push(Param::Private(arg.value));
            args_b.push(Param::Blind(arg.value.ty()));
        } else {
            args_a.push(Param::Public(arg.value));
            args_b.push(Param::Public(arg.value));
        }
    }
    (args_a, args_b)
}

fn to_vec(result: Option<Value>) -> Vec<Value> {
    match result {
        Some(val) => vec![val],
        None => vec![],
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

/// Classify an implementation error into a skip (expected/unsupported) or a
/// failure, per the implementation's [`SpecVm::is_expected_unsupported`].
fn classify<V: SpecVm>(err: V::Error) -> SkipReason {
    if V::is_expected_unsupported(&err) {
        SkipReason::Unsupported(format!("{:?}", err))
    } else {
        SkipReason::Failed(err.to_string())
    }
}

/// Compare two result vectors for equality, treating NaNs as equal.
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
                if a.is_nan() && b.is_nan() {
                } else if a.to_bits() != b.to_bits() {
                    return false;
                }
            }
            (Value::F64(a), Value::F64(b)) => {
                if a.is_nan() && b.is_nan() {
                } else if a.to_bits() != b.to_bits() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// Generate one `#[test]` per bundled spec suite for a [`SpecVm`] type.
///
/// `$vm` is the pair type implementing [`SpecVm`]; `$config` is an expression
/// evaluated (per test) to a [`SpecConfig`].
#[macro_export]
macro_rules! wasm_spec_tests {
    ($vm:ty, $config:expr) => {
        $crate::wasm_spec_test!($vm, $config, test_i32, I32);
        $crate::wasm_spec_test!($vm, $config, test_i64, I64);
        $crate::wasm_spec_test!($vm, $config, test_f32, F32);
        $crate::wasm_spec_test!($vm, $config, test_f64, F64);
        $crate::wasm_spec_test!($vm, $config, test_memory, MEMORY);
        $crate::wasm_spec_test!($vm, $config, test_local_get, LOCAL_GET);
        $crate::wasm_spec_test!($vm, $config, test_local_set, LOCAL_SET);
        $crate::wasm_spec_test!($vm, $config, test_local_tee, LOCAL_TEE);
        $crate::wasm_spec_test!($vm, $config, test_global, GLOBAL);
        $crate::wasm_spec_test!($vm, $config, test_block, BLOCK);
        $crate::wasm_spec_test!($vm, $config, test_loop, LOOP);
        $crate::wasm_spec_test!($vm, $config, test_if, IF);
        $crate::wasm_spec_test!($vm, $config, test_br, BR);
        $crate::wasm_spec_test!($vm, $config, test_br_if, BR_IF);
        $crate::wasm_spec_test!($vm, $config, test_br_table, BR_TABLE);
        $crate::wasm_spec_test!($vm, $config, test_return, RETURN);
        $crate::wasm_spec_test!($vm, $config, test_unreachable, UNREACHABLE);
        $crate::wasm_spec_test!($vm, $config, test_nop, NOP);
        $crate::wasm_spec_test!($vm, $config, test_func, FUNC);
        $crate::wasm_spec_test!($vm, $config, test_call, CALL);
        $crate::wasm_spec_test!($vm, $config, test_call_indirect, CALL_INDIRECT);
        $crate::wasm_spec_test!($vm, $config, test_select, SELECT);
        $crate::wasm_spec_test!($vm, $config, test_data, DATA);
        $crate::wasm_spec_test!($vm, $config, test_elem, ELEM);
        $crate::wasm_spec_test!($vm, $config, test_table, TABLE);
    };
}

/// Generate a single `#[test]` that runs one named suite against `$vm`.
#[macro_export]
macro_rules! wasm_spec_test {
    ($vm:ty, $config:expr, $name:ident, $suite:ident) => {
        #[test]
        fn $name() {
            let config = $config;
            let stats = $crate::run_suite::<$vm>($crate::suites::$suite, &config);
            println!(
                "{}: {} passed, {} failed, {} skipped",
                stringify!($suite),
                stats.passed,
                stats.failed,
                stats.skipped
            );
            for (category, count) in stats.skip_summary() {
                println!("  skipped {:>5}  {}", count, category);
            }
            for (i, msg) in stats.failure_messages.iter().enumerate() {
                println!("  failure {}. {}", i + 1, msg);
            }
            assert_eq!(stats.failed, 0, "{} suite had failures", stringify!($suite));
        }
    };
}
