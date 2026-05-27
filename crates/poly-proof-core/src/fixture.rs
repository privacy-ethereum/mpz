//! Circuit fixture.

use crate::{
    ConstraintId, ConstraintsBuilder, ExtensionField, Field, circuit::BuildError, gen_kernels,
    kernel::ConstraintDef,
};
use mpz_circuits_new::Context;
use mpz_poly_proof_macros::poly_kernel;

// ---------------------------------------------------------------------------
// Re-exports: the lifter-emitted `ConstraintDef` bundles under short
// names. The actual `impl ConstraintDef` blocks live in
// `crate::gen_kernels`, emitted by `build.rs`.
// ---------------------------------------------------------------------------

pub use gen_kernels::{
    GenAccMux as AccMux, GenAddrBaseMux as AddrBaseMux, GenAddrIndexMux as AddrIndexMux,
    GenCarryChain as CarryChain, GenCarryGenerate as CarryGenerate, GenFpMux as FpMux,
    GenMulBitExtraction as MulBitExtraction, GenMulForce as MulForce, GenPcMux as PcMux,
    GenSpMux as SpMux, GenWriteBack as WriteBack, GenWriteBackBit0 as WriteBackBit0,
};

// ---------------------------------------------------------------------------
// Registration helper
// ---------------------------------------------------------------------------

/// Step-circuit constraint set added to a builder.
pub struct StepConstraints {
    /// `ids[i]` is the [`ConstraintId`] of template `i`.
    pub ids: Vec<ConstraintId>,
    /// `counts[i]` is how many times template `i` is instantiated per step.
    pub counts: Vec<usize>,
    /// `num_vars[i]` is template `i`'s variable count.
    pub num_vars: Vec<usize>,
}

/// Register the 12 step-circuit constraints on `b` (with both kernels
/// attached atomically) and return their [`ConstraintId`]s, per-template
/// instantiation counts, and per-template variable counts.
pub fn add_step_constraints<E, W>(
    b: &mut ConstraintsBuilder<E, W>,
) -> Result<StepConstraints, BuildError>
where
    E: ExtensionField<W>,
    W: Field,
{
    let mut ids = Vec::with_capacity(12);
    let mut num_vars = Vec::with_capacity(12);
    // Register each template and record its arity.
    macro_rules! add {
        ($C:ty) => {{
            ids.push(b.add::<$C>()?);
            num_vars.push(<$C as ConstraintDef<E, W>>::NUM_VARS);
        }};
    }
    add!(CarryGenerate);
    add!(CarryChain);
    add!(WriteBack);
    add!(WriteBackBit0);
    add!(AddrBaseMux);
    add!(AddrIndexMux);
    add!(MulBitExtraction);
    add!(MulForce);
    add!(AccMux);
    add!(PcMux);
    add!(SpMux);
    add!(FpMux);

    let counts = vec![
        32, // carry generate
        32, // carry chain
        31, // write-back
        1,  // write-back
        20, // addr base mux
        32, // addr index mux
        1,  // MUL bit extraction
        1,  // MUL force
        32, // acc' MUX
        20, // PC' MUX
        12, // SP' MUX
        18, // FP' MUX
    ];

    Ok(StepConstraints {
        ids,
        counts,
        num_vars,
    })
}

// ---------------------------------------------------------------------------
// Coverage fixture
// ---------------------------------------------------------------------------

/// One constraint built to exercise every distinct code path in *both*
/// compilation pipelines — `compile`/`CircuitBuilder` (the DAG) and the
/// lifter (the kernels) — so a single differential test covers both.
#[poly_kernel(internal)]
pub fn coverage<C, E>(ctx: &mut C, vars: [C::Wire; 6]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    // Each var is a degree-1 wire `mac + value·X`: an Extension deg-0
    // coeff and a Subfield deg-1 coeff.
    let v0 = vars[0];
    let v1 = vars[1];
    let v2 = vars[2];
    let v3 = vars[3];
    let v4 = vars[4];
    let v5 = vars[5];

    // const one / zero — the emitter's `op_const_one` / `op_const_zero`
    // special cases (a degree-0 Extension slot / the Zero slot).
    let one = ctx.constant(E::one());
    let zero = ctx.constant(E::zero());

    // Mul, Var·Var — a single product spans all three mul slot-kind
    // combos: ext×ext (deg 0), ext×sub + sub×ext (deg 1, via
    // scale_by_subfield), sub×sub (deg 2).
    let p01 = ctx.mul(v0, v1); // deg 2
    let p23 = ctx.mul(v2, v3); // deg 2
    // Mul, Const·Var — Extension-only operand × a degree-1 operand.
    let cm = ctx.mul(one, v4); // deg 1
    // Mul, Mul·Var — degree-2 × degree-1 → deg 3.
    let mv = ctx.mul(p01, v5); // deg 3
    // Mul, Mul·Mul — degree-2 × degree-2 → deg 4 (top degree here).
    let mm = ctx.mul(p01, p23); // deg 4

    // Add, Var+Var — equal degree, no Δ-shift.
    let avv = ctx.add(v4, v5); // deg 1
    // Add, Var+Mul — unequal degree (1 vs 2): lower operand shifted up
    // by Δ¹ (top-aligned add).
    let avm = ctx.add(v0, p23); // deg 2
    // Add, Const+Mul — unequal degree (0 vs 3) → Δ³ shift.
    let acm = ctx.add(one, mv); // deg 3
    // Add, Add+Mul — unequal degree (1 vs 4) → Δ³ shift.
    let aam = ctx.add(avv, mm); // deg 4

    // Sub — lowers to `a + neg(b)`: exercises per-coefficient negation
    // (a Neg node), here across unequal degrees (3 − 1).
    let s = ctx.sub(mv, v1); // deg 3

    // Fold to one output through chained mixed-degree adds; the final
    // `+ zero` keeps a const-zero (Zero slot) live into the output.
    let t = ctx.add(avm, acm); // deg 3
    let t = ctx.add(t, aam); // deg 4
    let t = ctx.add(t, s); // deg 4
    let t = ctx.add(t, cm); // deg 4
    let t = ctx.add(t, zero); // deg 4

    ctx.assert_const(t, E::zero())
}
