//! WebAssembly spec-conformance tests for the ideal VM, via the shared
//! [`mpz_vm_test_harness`] harness.

use futures::{executor::block_on, future::try_join};
use mpz_common::context::test_st_context;
use mpz_vm_ir::Module;
use mpz_vm_core_new::{Param, Vm, value::Value};
use mpz_vm_ideal::{IdealError, Instance};
use mpz_vm_test_harness::{SpecConfig, SpecVm};

/// A pair of ideal-VM instances (single party each, exchanging over an
/// in-process channel).
struct IdealPair {
    a: Instance,
    b: Instance,
}

impl SpecVm for IdealPair {
    type Error = IdealError;

    fn instantiate(module: &Module, _variant: &str) -> Result<Self, String> {
        Ok(Self {
            a: Instance::new(module.clone()).map_err(|e| format!("{:?}", e))?,
            b: Instance::new(module.clone()).map_err(|e| format!("{:?}", e))?,
        })
    }

    fn run(
        &mut self,
        func_idx: u32,
        params_a: Vec<Param>,
        params_b: Vec<Param>,
    ) -> Result<(Option<Value>, Option<Value>), IdealError> {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        block_on(try_join(
            self.a.call(&mut ctx_a, func_idx, params_a),
            self.b.call(&mut ctx_b, func_idx, params_b),
        ))
    }

    fn is_expected_unsupported(err: &IdealError) -> bool {
        err.is_expected_unsupported()
    }
}

mpz_vm_test_harness::wasm_spec_tests!(IdealPair, SpecConfig::default());
