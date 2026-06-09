//! Behavioral tests for the embedder memory I/O surface — [`Vm::write`],
//! [`Vm::reveal`], and [`Vm::read`] — kept separate from the WebAssembly core
//! spec conformance tests in the crate root.
//!
//! Where the spec tests drive guest functions and compare return values, these
//! exercise the *host* side of the embedder: queuing private/blind/public
//! writes, revealing symbolic ranges, and reading concrete bytes back, across a
//! two-party pair. The pluggable surface is [`MemVm`]; [`scenarios`] lists the
//! fixed scenarios and [`run_scenarios`] checks an implementation against them.
//!
//! Generate a single `#[test]` for an implementation with
//! [`mem_behavior_tests!`].
//!
//! [`Vm::write`]: mpz_vm_core_new::Vm::write
//! [`Vm::reveal`]: mpz_vm_core_new::Vm::reveal
//! [`Vm::read`]: mpz_vm_core_new::Vm::read

use mpz_vm_ir::{ExportKind, Module};
use mpz_vm_core_new::value::Value;

/// A two-party implementation exercised through the memory I/O surface.
///
/// Party A holds [`MemStep::WritePrivateA`] bytes (party B sees them blind);
/// party B holds [`MemStep::WritePrivateB`] bytes (party A sees them blind).
pub trait MemVm: Sized {
    /// The error type reported by a scenario run.
    type Error: core::error::Error;

    /// Construct a fresh party pair for `module`. `Err` carries a
    /// human-readable reason.
    fn instantiate(module: &Module) -> Result<Self, String>;

    /// Drive a scripted scenario on the pair, applying each [`MemStep`] to both
    /// parties (queuing I/O, flushing on [`MemStep::Call`]) and returning the
    /// ordered [`Observation`]s produced by the `Read` and `Call` steps.
    fn run_scenario(&mut self, steps: &[MemStep]) -> Result<Vec<Observation>, Self::Error>;

    /// Classify a mid-scenario error: `true` => an expected/unsupported
    /// condition, counted as a skip; `false` => a real failure.
    fn is_expected_unsupported(err: &Self::Error) -> bool;
}

/// One step of a memory I/O scenario, applied to both parties.
#[derive(Clone, Debug)]
pub enum MemStep {
    /// Party A writes `bytes` privately at `ptr`; party B writes blind over the
    /// same range. After a flush both sides hold the bytes (symbolically).
    WritePrivateA { ptr: u32, bytes: Vec<u8> },
    /// Party B writes `bytes` privately at `ptr`; party A writes blind.
    WritePrivateB { ptr: u32, bytes: Vec<u8> },
    /// Both parties write the same public bytes at `ptr`. The range stays
    /// concrete and is readable without a flush.
    WritePublic { ptr: u32, bytes: Vec<u8> },
    /// Party A writes `bytes_a` as public, party B writes `bytes_b` as public,
    /// at `ptr`. Models a host that feeds the two parties *inconsistent* public
    /// inputs — public data is assumed identical on both sides, so a downstream
    /// [`MemStep::CheckedCall`] must surface the divergence.
    WritePublicDivergent {
        ptr: u32,
        bytes_a: Vec<u8>,
        bytes_b: Vec<u8>,
    },
    /// Both parties queue a reveal of `ptr..ptr+len`. Takes effect on the next
    /// flush, after which the range is concrete.
    Reveal { ptr: u32, len: usize },
    /// Invoke the exported function `func` with public `args` on both parties.
    /// Flushes any pending writes/reveals first. Records a [`Observation::Call`]
    /// with each party's return value. A no-op export flushes without computing.
    Call { func: String, args: Vec<Value> },
    /// Like [`MemStep::Call`], but both parties are driven to completion even if
    /// one errors, and the step records whether they *agreed* on a valid result
    /// ([`Observation::Agreement`]). Used to assert that inconsistent inputs are
    /// not silently reconciled into a single accepted answer.
    CheckedCall { func: String, args: Vec<Value> },
    /// Both parties read `ptr..ptr+len`. Records a [`Observation::Read`] with
    /// each party's outcome (bytes, or a failure for a symbolic/pending range).
    Read { ptr: u32, len: usize },
}

/// One party's outcome for a [`MemStep::Read`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// The range was concrete; these bytes were read.
    Ok(Vec<u8>),
    /// The range could not be read (symbolic, or a pending blind region).
    Err,
}

/// Whether a [`MemStep::CheckedCall`] reached cross-party agreement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Agreement {
    /// Both parties returned a value and the values were equal.
    Agreed,
    /// The parties disagreed — different values, or one/both errored.
    Disagreed,
}

/// An observation recorded by a [`MemStep`], holding both parties' results so
/// the harness can assert cross-party agreement.
#[derive(Clone, Debug, PartialEq)]
pub enum Observation {
    /// A read step: each party's [`ReadOutcome`].
    Read { a: ReadOutcome, b: ReadOutcome },
    /// A call step: each party's return value.
    Call { a: Option<Value>, b: Option<Value> },
    /// A checked-call step: whether the parties agreed.
    Agreement(Agreement),
}

/// The outcome of running one scenario against an implementation.
#[derive(Debug)]
pub enum ScenarioOutcome {
    /// Observations matched the expectation.
    Pass,
    /// The implementation raised an expected/unsupported error (per
    /// [`MemConfig`]).
    Skip(String),
    /// A real failure: a mismatch, or an unexpected error.
    Fail(String),
}

/// A named memory I/O scenario: a module, the steps to run, and the expected
/// observations.
pub struct Scenario {
    /// Identifier reported in the test output.
    pub name: &'static str,
    /// The guest module (WAT source).
    pub wat: String,
    /// Steps applied to the pair.
    pub steps: Vec<MemStep>,
    /// The observations [`run_scenario`](MemVm::run_scenario) must produce.
    pub expected: Vec<Observation>,
}

/// Parse a WAT module string into a [`Module`].
pub fn parse_module(wat: &str) -> Result<Module, String> {
    let binary = wat::parse_str(wat).map_err(|e| format!("WAT parse: {e}"))?;
    Module::parse(&binary).map_err(|e| format!("Module parse: {e:?}"))
}

/// Resolve an exported function's index by name.
pub fn func_index(module: &Module, name: &str) -> Option<u32> {
    module.exports().iter().find_map(|e| match e.kind {
        ExportKind::Func(idx) if e.name == name => Some(idx),
        _ => None,
    })
}

/// The fixed set of memory I/O behavioral scenarios.
pub fn scenarios() -> Vec<Scenario> {
    vec![
        public_write_read(),
        private_reveal_roundtrip_a(),
        private_reveal_roundtrip_b(),
        private_write_feeds_load(),
        consistent_public_checked_call(),
        inconsistent_public_write_disagrees(),
        inconsistent_public_feeds_authenticated_op(),
    ]
}

/// Run every scenario against `V`, returning `(name, outcome)` per scenario.
pub fn run_scenarios<V: MemVm>() -> Vec<(&'static str, ScenarioOutcome)> {
    scenarios()
        .into_iter()
        .map(|s| (s.name, check::<V>(&s)))
        .collect()
}

fn check<V: MemVm>(s: &Scenario) -> ScenarioOutcome {
    let module = match parse_module(&s.wat) {
        Ok(m) => m,
        Err(e) => return ScenarioOutcome::Fail(e),
    };
    let mut vm = match V::instantiate(&module) {
        Ok(vm) => vm,
        Err(e) => return ScenarioOutcome::Fail(format!("instantiate: {e}")),
    };
    match vm.run_scenario(&s.steps) {
        Ok(obs) if obs == s.expected => ScenarioOutcome::Pass,
        Ok(obs) => ScenarioOutcome::Fail(format!(
            "observation mismatch:\n   got: {obs:?}\n   exp: {:?}",
            s.expected
        )),
        Err(e) if V::is_expected_unsupported(&e) => ScenarioOutcome::Skip(format!("{e:?}")),
        Err(e) => ScenarioOutcome::Fail(format!("run_scenario: {e:?}")),
    }
}

/// A module exporting only a no-op `flush` function over one memory page.
fn flush_module() -> String {
    r#"(module (memory 1) (func (export "flush")))"#.to_string()
}

fn flush() -> MemStep {
    MemStep::Call {
        func: "flush".to_string(),
        args: vec![],
    }
}

/// Public bytes are concrete on both sides and readable immediately, with no
/// flush.
fn public_write_read() -> Scenario {
    let bytes = vec![1, 2, 3, 4];
    Scenario {
        name: "public_write_read",
        wat: r#"(module (memory 1))"#.to_string(),
        steps: vec![
            MemStep::WritePublic {
                ptr: 0,
                bytes: bytes.clone(),
            },
            MemStep::Read { ptr: 0, len: 4 },
        ],
        expected: vec![Observation::Read {
            a: ReadOutcome::Ok(bytes.clone()),
            b: ReadOutcome::Ok(bytes),
        }],
    }
}

/// A private write from party A is symbolic after flush (unreadable on both
/// sides) and becomes concrete only after a reveal; the revealed bytes match
/// what A wrote and agree across parties.
fn private_reveal_roundtrip_a() -> Scenario {
    let bytes = vec![0xde, 0xad, 0xbe, 0xef];
    Scenario {
        name: "private_reveal_roundtrip_a",
        wat: flush_module(),
        steps: vec![
            MemStep::WritePrivateA {
                ptr: 0,
                bytes: bytes.clone(),
            },
            flush(),
            MemStep::Read { ptr: 0, len: 4 },
            MemStep::Reveal { ptr: 0, len: 4 },
            flush(),
            MemStep::Read { ptr: 0, len: 4 },
        ],
        expected: vec![
            Observation::Call { a: None, b: None },
            Observation::Read {
                a: ReadOutcome::Err,
                b: ReadOutcome::Err,
            },
            Observation::Call { a: None, b: None },
            Observation::Read {
                a: ReadOutcome::Ok(bytes.clone()),
                b: ReadOutcome::Ok(bytes),
            },
        ],
    }
}

/// As [`private_reveal_roundtrip_a`] but the private writer is party B.
fn private_reveal_roundtrip_b() -> Scenario {
    let bytes = vec![0x01, 0x23, 0x45, 0x67];
    Scenario {
        name: "private_reveal_roundtrip_b",
        wat: flush_module(),
        steps: vec![
            MemStep::WritePrivateB {
                ptr: 8,
                bytes: bytes.clone(),
            },
            flush(),
            MemStep::Read { ptr: 8, len: 4 },
            MemStep::Reveal { ptr: 8, len: 4 },
            flush(),
            MemStep::Read { ptr: 8, len: 4 },
        ],
        expected: vec![
            Observation::Call { a: None, b: None },
            Observation::Read {
                a: ReadOutcome::Err,
                b: ReadOutcome::Err,
            },
            Observation::Call { a: None, b: None },
            Observation::Read {
                a: ReadOutcome::Ok(bytes.clone()),
                b: ReadOutcome::Ok(bytes),
            },
        ],
    }
}

/// A private write feeds a guest computation: the bytes land in linear memory
/// (symbolically) and a function that loads and increments them returns the
/// right value on both parties.
fn private_write_feeds_load() -> Scenario {
    let wat = r#"(module
        (memory 1)
        (func (export "loadadd") (result i32)
            i32.const 0 i32.load i32.const 1 i32.add))"#
        .to_string();
    Scenario {
        name: "private_write_feeds_load",
        wat,
        steps: vec![
            MemStep::WritePrivateA {
                ptr: 0,
                bytes: 7i32.to_le_bytes().to_vec(),
            },
            MemStep::Call {
                func: "loadadd".to_string(),
                args: vec![],
            },
        ],
        expected: vec![Observation::Call {
            a: Some(Value::I32(8)),
            b: Some(Value::I32(8)),
        }],
    }
}

/// A module loading and returning the public `i32` at address 0.
fn load0_module() -> String {
    r#"(module
        (memory 1)
        (func (export "load0") (result i32) i32.const 0 i32.load))"#
        .to_string()
}

/// Control for the divergent case: when both parties get the *same* public
/// bytes, a checked call agrees.
fn consistent_public_checked_call() -> Scenario {
    Scenario {
        name: "consistent_public_checked_call",
        wat: load0_module(),
        steps: vec![
            MemStep::WritePublic {
                ptr: 0,
                bytes: 5i32.to_le_bytes().to_vec(),
            },
            MemStep::CheckedCall {
                func: "load0".to_string(),
                args: vec![],
            },
        ],
        expected: vec![Observation::Agreement(Agreement::Agreed)],
    }
}

/// Inconsistent public writes: the two parties are fed different "public" bytes.
/// A checked call must surface the divergence rather than silently agree.
fn inconsistent_public_write_disagrees() -> Scenario {
    Scenario {
        name: "inconsistent_public_write_disagrees",
        wat: load0_module(),
        steps: vec![
            MemStep::WritePublicDivergent {
                ptr: 0,
                bytes_a: 5i32.to_le_bytes().to_vec(),
                bytes_b: 9i32.to_le_bytes().to_vec(),
            },
            MemStep::CheckedCall {
                func: "load0".to_string(),
                args: vec![],
            },
        ],
        expected: vec![Observation::Agreement(Agreement::Disagreed)],
    }
}

/// Inconsistent public bytes feeding an *authenticated* op (added to a private
/// value). A prover/verifier implementation rejects this cryptographically — the
/// divergent public wire breaks the proof — while a plain reference implementation
/// simply computes different results; either way the parties must not agree.
fn inconsistent_public_feeds_authenticated_op() -> Scenario {
    let wat = r#"(module
        (memory 1)
        (func (export "f") (result i32)
            i32.const 0 i32.load
            i32.const 8 i32.load
            i32.add))"#
        .to_string();
    Scenario {
        name: "inconsistent_public_feeds_authenticated_op",
        wat,
        steps: vec![
            // mem[0]: a private value (held by party A, blind to B).
            MemStep::WritePrivateA {
                ptr: 0,
                bytes: 1i32.to_le_bytes().to_vec(),
            },
            // mem[8]: inconsistent "public" value across the parties.
            MemStep::WritePublicDivergent {
                ptr: 8,
                bytes_a: 5i32.to_le_bytes().to_vec(),
                bytes_b: 9i32.to_le_bytes().to_vec(),
            },
            MemStep::CheckedCall {
                func: "f".to_string(),
                args: vec![],
            },
        ],
        expected: vec![Observation::Agreement(Agreement::Disagreed)],
    }
}

/// Generate a `#[test]` running every behavioral scenario against `$vm`.
#[macro_export]
macro_rules! mem_behavior_tests {
    ($vm:ty) => {
        #[test]
        fn mem_behavior() {
            let results = $crate::behavior::run_scenarios::<$vm>();
            let mut failed = 0usize;
            for (name, outcome) in &results {
                match outcome {
                    $crate::behavior::ScenarioOutcome::Pass => println!("ok   {name}"),
                    $crate::behavior::ScenarioOutcome::Skip(why) => {
                        println!("skip {name}: {why}")
                    }
                    $crate::behavior::ScenarioOutcome::Fail(msg) => {
                        failed += 1;
                        println!("FAIL {name}: {msg}");
                    }
                }
            }
            assert_eq!(failed, 0, "{failed} behavioral scenario(s) failed");
        }
    };
}
