//! Tracing: the [`Context`] impl that records constraint operations
//! as an [`Ir`]. Running a `mpz_circuits_new`-style constraint function
//! against [`KernelEmitter`] produces an `Ir` whose slot kinds are
//! determined by [`crate::algebra`].

use std::marker::PhantomData;

use mpz_circuits_new::Context;
use mpz_fields::{ExtensionField, Field};

use crate::{
    algebra::{add_slot_kinds, mul_slot_kinds},
    ir::{ConstVal, Ir, IrNode, NodeHandle, Op, SlotKind},
};

pub struct KernelEmitter<E: Field, W: Field>
where
    E: ExtensionField<W>,
{
    ir: Ir,
    _ph: PhantomData<(E, W)>,
}

#[derive(Debug, thiserror::Error)]
pub enum LifterError {
    #[error("constraint closure emitted no assertion")]
    NoConstraint,
    #[error("constraint closure emitted multiple assertions")]
    MultipleConstraints,
    #[error("only `E::zero()` and `E::one()` are supported as constants in this lifter")]
    UnsupportedConstant,
    #[error("`assert_const(v, c)` requires `c == E::zero()` for this lifter")]
    NonZeroAssertion,
}

impl<E, W> KernelEmitter<E, W>
where
    E: ExtensionField<W>,
    W: Field,
{
    fn new() -> Self {
        Self {
            ir: Ir {
                num_vars: 0,
                nodes: Vec::new(),
                output: None,
            },
            _ph: PhantomData,
        }
    }

    fn alloc_var(&mut self, idx: usize) -> NodeHandle {
        self.ir.num_vars = self.ir.num_vars.max(idx + 1);
        self.push(IrNode {
            op: Op::Var(idx),
            degree: 1,
            slot_kinds: vec![SlotKind::Extension, SlotKind::Subfield],
        })
    }

    fn push(&mut self, node: IrNode) -> NodeHandle {
        let h = NodeHandle(self.ir.nodes.len());
        self.ir.nodes.push(node);
        h
    }

    fn finish(self) -> Result<Ir, LifterError> {
        if self.ir.output.is_none() {
            return Err(LifterError::NoConstraint);
        }
        Ok(self.ir)
    }
}

impl<E, W> Context for KernelEmitter<E, W>
where
    E: ExtensionField<W>,
    W: Field,
{
    type Error = LifterError;
    type Wire = NodeHandle;
    type Field = E;

    fn add(&mut self, a: Self::Wire, b: Self::Wire) -> Self::Wire {
        let na = &self.ir.nodes[a.0];
        let nb = &self.ir.nodes[b.0];
        let slot_kinds = add_slot_kinds(&na.slot_kinds, na.degree, &nb.slot_kinds, nb.degree);
        let degree = na.degree.max(nb.degree);
        self.push(IrNode {
            op: Op::Add(a, b),
            degree,
            slot_kinds,
        })
    }

    fn sub(&mut self, a: Self::Wire, b: Self::Wire) -> Self::Wire {
        let neg_b = self.ir.op_neg(b);
        self.add(a, neg_b)
    }

    fn mul(&mut self, a: Self::Wire, b: Self::Wire) -> Self::Wire {
        let na = &self.ir.nodes[a.0];
        let nb = &self.ir.nodes[b.0];
        let slot_kinds = mul_slot_kinds(&na.slot_kinds, &nb.slot_kinds);
        let degree = na.degree + nb.degree;
        self.push(IrNode {
            op: Op::Mul(a, b),
            degree,
            slot_kinds,
        })
    }

    fn constant(&mut self, v: Self::Field) -> Self::Wire {
        let cv = if v == E::zero() {
            ConstVal::Zero
        } else if v == E::one() {
            ConstVal::One
        } else {
            // All step-circuit fixtures only use 0 / 1.
            panic!("KernelEmitter only supports E::zero() and E::one() constants");
        };
        let kind = match cv {
            ConstVal::Zero => SlotKind::Zero,
            // Const(1) is `embed(W::one())`, hence subfield-tracked.
            ConstVal::One => SlotKind::Subfield,
        };
        self.push(IrNode {
            op: Op::Const(cv),
            degree: 0,
            slot_kinds: vec![kind],
        })
    }

    fn assert_const(&mut self, v: Self::Wire, expected: Self::Field) -> Result<(), Self::Error> {
        if expected != E::zero() {
            return Err(LifterError::NonZeroAssertion);
        }
        if self.ir.output.is_some() {
            return Err(LifterError::MultipleConstraints);
        }
        self.ir.output = Some(v);
        Ok(())
    }
}

/// Run `constraint` against a [`KernelEmitter`] and return the IR.
pub fn trace_constraint<E, W, F, const N: usize>(constraint: F) -> Result<Ir, LifterError>
where
    E: ExtensionField<W>,
    W: Field,
    F: FnOnce(&mut KernelEmitter<E, W>, [NodeHandle; N]) -> Result<(), LifterError>,
{
    let mut emitter = KernelEmitter::<E, W>::new();
    let vars: [NodeHandle; N] = std::array::from_fn(|i| emitter.alloc_var(i));
    constraint(&mut emitter, vars)?;
    emitter.finish()
}
