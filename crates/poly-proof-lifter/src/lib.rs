//! Lifter: trace a constraint written against [`mpz_circuits_new::Context`]
//! and produce a structurally-typed IR that captures the QuickSilver
//! polynomial lift's slot-kind algebra.
//!
//! Pipeline:
//!
//! ```text
//!  Constraint fn (over &mut C: Context)
//!         │
//!         │  1) trace_constraint
//!         ▼
//!        Ir
//!         │
//!         │  2) emit_prover / emit_verifier
//!         ▼
//!  Generated kernels
//!  (impl ProverKernel + impl VerifierKernel)
//! ```
//!
//!
//! Modules:
//!
//! * [`ir`] — the IR types ([`Ir`], [`IrNode`], [`Op`], [`SlotKind`], …).
//! * `algebra` — pure slot-kind propagation rules (`pub(crate)`, consumed only
//!   by [`trace`]).
//! * [`trace`] — the [`Context`] impl ([`KernelEmitter`]) that records
//!   operations and the [`trace_constraint`] entry point.
//! * [`emit`] — source emitter: turns an [`Ir`] into Rust `impl ProverKernel` /
//!   `impl VerifierKernel` source ready to be `include!`'d into a host crate.

#![allow(dead_code)]

pub(crate) mod algebra;
pub mod emit;
pub mod ir;
#[cfg(test)]
mod test_utils;
pub mod trace;

pub use emit::{Paths, emit_constraint_def, emit_prover, emit_verifier};
pub use ir::{ConstVal, Ir, IrNode, NodeHandle, Op, SlotKind};
pub use trace::{KernelEmitter, LifterError, trace_constraint};

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuits_new::fixtures;
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};

    /// Spot-check: emitted source contains the recognizable shape.
    #[test]
    fn emit_mul_force_smoke() {
        let ir = trace_constraint::<Gf2_64, Gf2, _, 3>(|ctx, vars| {
            fixtures::mul_force(ctx, vars).map_err(|_| LifterError::NoConstraint)
        })
        .unwrap();
        let src = emit_prover("MulForceKernel", &ir, &Paths::default());
        assert!(src.contains("pub struct MulForceKernel;"));
        assert!(src.contains("const NUM_VARS: usize = 3;"));
        assert!(src.contains("const DEGREE: usize = 2;"));
        assert!(src.contains("scale_by_subfield"));
        assert!(src.contains("accumulators[n - 2]"));
        assert!(src.contains("accumulators[n - 1]"));
    }

    /// Per-fixture shape assertions on the prover kernel emitted by
    /// the lifter.
    ///
    /// Expected values come from independent knowledge of each
    /// constraint:
    ///   * `num_vars` / `degree` — derived from the constraint's definition.
    ///   * op counts — snapshotted from the hand-tuned reference kernels.
    ///
    /// Catches two regression classes that behavioral tests miss:
    ///   1. Bad consts — kernel declares wrong arity or polynomial degree.
    ///   2. Optimization regression — kernel computes the right value but via a
    ///      suboptimal path (e.g., a full E×E multiply where
    ///      `scale_by_subfield` should have been chosen, or eagerly lifting a
    ///      subfield value to extension where it could have stayed subfield).
    #[test]
    fn emitted_kernel_matches_expected_shape() {
        #[derive(Debug, PartialEq, Eq)]
        struct KernelShape {
            /// `const NUM_VARS: usize = …;` literal.
            num_vars: usize,
            /// `const DEGREE: usize = …;` literal.
            degree: usize,
            /// `.scale_by_subfield(W)` calls.
            scale_by_subfield: usize,
            /// `E::embed(W)` calls.
            embed: usize,
            /// `* chi` occurrences.
            chi_mul: usize,
            /// `accumulators[` occurrences.
            accumulator_access: usize,
        }

        /// Parse `const <name>: usize = N;` out of an emitted kernel
        /// source string.
        fn parse_const(src: &str, name: &str) -> usize {
            let pat = format!("const {name}: usize = ");
            let start = src.find(&pat).expect("const not found") + pat.len();
            let end = src[start..].find(';').expect("const missing terminator");
            src[start..start + end]
                .trim()
                .parse()
                .expect("const literal not a usize")
        }

        macro_rules! check {
            ($name:literal, $fixture:path, $num_vars:literal, $expected:expr $(,)?) => {{
                let ir = trace_constraint::<Gf2_64, Gf2, _, $num_vars>(|ctx, vars| {
                    $fixture(ctx, vars).map_err(|_| LifterError::NoConstraint)
                })
                .unwrap();
                let src = emit_prover($name, &ir, &Paths::default());
                let actual = KernelShape {
                    num_vars: parse_const(&src, "NUM_VARS"),
                    degree: parse_const(&src, "DEGREE"),
                    scale_by_subfield: src.matches("scale_by_subfield(").count(),
                    embed: src.matches("E::embed(").count(),
                    chi_mul: src.matches("* chi").count(),
                    accumulator_access: src.matches("accumulators[").count(),
                };
                assert_eq!(actual, $expected, "kernel-shape mismatch for {}", $name);
            }};
        }

        check!(
            "MulForceKernel",
            fixtures::mul_force,
            3,
            KernelShape {
                num_vars: 3,
                degree: 2,
                scale_by_subfield: 2,
                embed: 0,
                chi_mul: 2,
                accumulator_access: 4,
            }
        );

        check!(
            "FpMuxKernel",
            fixtures::fp_mux,
            4,
            KernelShape {
                num_vars: 4,
                degree: 2,
                scale_by_subfield: 2,
                embed: 0,
                chi_mul: 2,
                accumulator_access: 4,
            }
        );

        check!(
            "CarryChainKernel",
            fixtures::carry_chain,
            4,
            KernelShape {
                num_vars: 4,
                degree: 2,
                scale_by_subfield: 2,
                embed: 0,
                chi_mul: 2,
                accumulator_access: 4,
            }
        );

        check!(
            "AddrIndexMuxKernel",
            fixtures::addr_index_mux,
            4,
            KernelShape {
                num_vars: 4,
                degree: 2,
                scale_by_subfield: 2,
                embed: 0,
                chi_mul: 2,
                accumulator_access: 4,
            }
        );

        check!(
            "CarryGenerateKernel",
            fixtures::carry_generate,
            5,
            KernelShape {
                num_vars: 5,
                degree: 3,
                scale_by_subfield: 5,
                embed: 0,
                chi_mul: 3,
                accumulator_access: 6,
            }
        );

        check!(
            "AddrBaseMuxKernel",
            fixtures::addr_base_mux,
            6,
            KernelShape {
                num_vars: 6,
                degree: 3,
                scale_by_subfield: 7,
                embed: 0,
                chi_mul: 3,
                accumulator_access: 6,
            }
        );

        check!(
            "AccMuxKernel",
            fixtures::acc_mux,
            6,
            KernelShape {
                num_vars: 6,
                degree: 3,
                scale_by_subfield: 5,
                embed: 0,
                chi_mul: 3,
                accumulator_access: 6,
            }
        );

        check!(
            "SpMuxKernel",
            fixtures::sp_mux,
            6,
            KernelShape {
                num_vars: 6,
                degree: 3,
                scale_by_subfield: 5,
                embed: 0,
                chi_mul: 3,
                accumulator_access: 6,
            }
        );

        check!(
            "PcMuxKernel",
            fixtures::pc_mux,
            8,
            KernelShape {
                num_vars: 8,
                degree: 4,
                scale_by_subfield: 11,
                embed: 0,
                chi_mul: 4,
                accumulator_access: 8,
            }
        );

        check!(
            "WriteBackKernel",
            fixtures::write_back,
            13,
            KernelShape {
                num_vars: 13,
                degree: 6,
                scale_by_subfield: 20,
                embed: 0,
                chi_mul: 6,
                accumulator_access: 12,
            }
        );

        check!(
            "WriteBackBit0Kernel",
            fixtures::write_back_bit0,
            14,
            KernelShape {
                num_vars: 14,
                degree: 6,
                scale_by_subfield: 20,
                embed: 0,
                chi_mul: 6,
                accumulator_access: 12,
            }
        );

        check!(
            "MulBitExtractionKernel",
            fixtures::mul_bit_extraction,
            38,
            KernelShape {
                num_vars: 38,
                degree: 6,
                scale_by_subfield: 88,
                embed: 0,
                chi_mul: 6,
                accumulator_access: 12,
            }
        );
    }
}
