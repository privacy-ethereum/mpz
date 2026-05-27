//! Constraint types.

use crate::{
    ExtensionField, Field,
    circuit::{BuildError, Circuit, CircuitBuilder, NodeId, compile},
    kernel::{ConstraintDef, ProverKernel, VerifierKernel},
};

/// Identifier for a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConstraintId(pub(crate) usize);

/// Concrete entry in the prover-side kernel registry.
#[derive(Clone, Copy)]
pub struct ProverKernelEntry<E: Field, W: Field> {
    /// [`ProverKernel::accumulate`] impl.
    pub(crate) accumulate: fn(&[E], &[W], E, &mut [E]),
    /// Variable count.
    pub(crate) num_vars: usize,
    /// Polynomial degree.
    pub(crate) degree: usize,
}

/// Concrete entry in the verifier-side kernel registry.
#[derive(Clone, Copy)]
pub struct VerifierKernelEntry<E: Field> {
    /// [`VerifierKernel::evaluate`] impl.
    pub(crate) evaluate: fn(&[E], &[E]) -> E,
    /// Variable count.
    pub(crate) num_vars: usize,
    /// Polynomial degree.
    pub(crate) degree: usize,
}

/// Body of a prover-side constraint.
#[derive(Clone)]
pub(crate) enum ProverConstraint<E: Field, W: Field> {
    /// Kernel constraint.
    Kernel(ProverKernelEntry<E, W>),
    /// Runtime-defined constraint.
    Circuit(Circuit<E>),
}

/// Body of a verifier-side constraint.
#[derive(Clone)]
pub(crate) enum VerifierConstraint<E: Field> {
    /// Kernel constraint.
    Kernel(VerifierKernelEntry<E>),
    /// Runtime-defined constraint.
    Circuit(Circuit<E>),
}

/// Constraint set for the prover.
pub struct ProverConstraints<E: Field, W: Field = E> {
    pub(crate) bodies: Vec<ProverConstraint<E, W>>,
}

impl<E: Field, W: Field> Clone for ProverConstraints<E, W> {
    fn clone(&self) -> Self {
        Self {
            bodies: self.bodies.clone(),
        }
    }
}

/// Constraint set for the verifier.
pub struct VerifierConstraints<E: Field> {
    pub(crate) bodies: Vec<VerifierConstraint<E>>,
}

impl<E: Field> Clone for VerifierConstraints<E> {
    fn clone(&self) -> Self {
        Self {
            bodies: self.bodies.clone(),
        }
    }
}

/// Constraint builder.
pub struct ConstraintsBuilder<E: Field, W: Field = E> {
    entries: Vec<BuilderEntry<E, W>>,
}

impl<E: Field, W: Field> Default for ConstraintsBuilder<E, W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Field, W: Field> ConstraintsBuilder<E, W> {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a constraint defined by a [`ConstraintDef`] type.
    ///
    /// This is the canonical registration path for constraints known at compile
    /// time.
    pub fn add<C>(&mut self) -> Result<ConstraintId, BuildError>
    where
        C: ConstraintDef<E, W>,
        E: ExtensionField<W>,
    {
        let prover = ProverKernelEntry {
            accumulate: <C::ProverKernel as ProverKernel<E, W>>::accumulate,
            num_vars: C::NUM_VARS,
            degree: C::DEGREE,
        };
        let verifier = VerifierKernelEntry {
            evaluate: <C::VerifierKernel as VerifierKernel<E>>::evaluate,
            num_vars: C::NUM_VARS,
            degree: C::DEGREE,
        };
        let id = ConstraintId(self.entries.len());
        self.entries
            .push(BuilderEntry::Kernels { prover, verifier });
        Ok(id)
    }

    /// Register a runtime-defined constraint via a closure.
    pub fn add_dynamic<F>(&mut self, num_vars: usize, f: F) -> Result<ConstraintId, BuildError>
    where
        F: FnOnce(&mut CircuitBuilder<E>, &[NodeId]) -> Result<(), BuildError>,
    {
        let circuit = compile(num_vars, f)?;
        let id = ConstraintId(self.entries.len());
        self.entries.push(BuilderEntry::Circuit(circuit));
        Ok(id)
    }

    /// Number of constraints registered so far.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no constraints have been registered yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Freeze into both prover and verifier outputs.
    pub fn build(self) -> (ProverConstraints<E, W>, VerifierConstraints<E>) {
        let mut prover_bodies = Vec::with_capacity(self.entries.len());
        let mut verifier_bodies = Vec::with_capacity(self.entries.len());
        for entry in self.entries {
            match entry {
                BuilderEntry::Kernels { prover, verifier } => {
                    prover_bodies.push(ProverConstraint::Kernel(prover));
                    verifier_bodies.push(VerifierConstraint::Kernel(verifier));
                }
                BuilderEntry::Circuit(c) => {
                    prover_bodies.push(ProverConstraint::Circuit(c.clone()));
                    verifier_bodies.push(VerifierConstraint::Circuit(c));
                }
            }
        }
        (
            ProverConstraints {
                bodies: prover_bodies,
            },
            VerifierConstraints {
                bodies: verifier_bodies,
            },
        )
    }

    /// Freeze into the prover-side output only.
    pub fn build_prover(self) -> ProverConstraints<E, W> {
        let bodies = self
            .entries
            .into_iter()
            .map(|e| match e {
                BuilderEntry::Kernels { prover, .. } => ProverConstraint::Kernel(prover),
                BuilderEntry::Circuit(c) => ProverConstraint::Circuit(c),
            })
            .collect();
        ProverConstraints { bodies }
    }

    /// Freeze into the verifier-side output only.
    pub fn build_verifier(self) -> VerifierConstraints<E> {
        let bodies = self
            .entries
            .into_iter()
            .map(|e| match e {
                BuilderEntry::Kernels { verifier, .. } => VerifierConstraint::Kernel(verifier),
                BuilderEntry::Circuit(c) => VerifierConstraint::Circuit(c),
            })
            .collect();
        VerifierConstraints { bodies }
    }
}

/// Per-constraint entry inside the builder.
enum BuilderEntry<E: Field, W: Field> {
    Kernels {
        prover: ProverKernelEntry<E, W>,
        verifier: VerifierKernelEntry<E>,
    },
    Circuit(Circuit<E>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::CarryChain;
    use mpz_circuits_new::fixtures::and_gate;
    use mpz_fields::{gf2::Gf2, gf2_64::Gf2_64};

    /// Register the upstream 3-var `and_gate` via the runtime
    /// (`add_dynamic`) path — the Circuit-body counterpart to the
    /// kernel-attached `add::<CarryChain>()`.
    fn add_and_gate(b: &mut ConstraintsBuilder<Gf2_64, Gf2>) -> ConstraintId {
        b.add_dynamic(3, |cb, vars| {
            let arr: [_; 3] = vars.try_into().unwrap();
            and_gate(cb, arr)
        })
        .unwrap()
    }

    /// One kernel constraint then one dynamic constraint — the canonical
    /// mixed sequence the projection tests below replay.
    fn register_mixed(b: &mut ConstraintsBuilder<Gf2_64, Gf2>) {
        b.add::<CarryChain>().unwrap();
        add_and_gate(b);
    }

    #[test]
    fn len_and_is_empty_track_registrations() {
        let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);

        b.add::<CarryChain>().unwrap();
        assert!(!b.is_empty());
        assert_eq!(b.len(), 1);

        add_and_gate(&mut b);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn ids_are_sequential_across_mixed_paths() {
        let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
        let a = b.add::<CarryChain>().unwrap(); // kernel
        let c = add_and_gate(&mut b); // dynamic
        let d = b.add::<CarryChain>().unwrap(); // kernel again
        assert_eq!((a.0, c.0, d.0), (0, 1, 2));
    }

    #[test]
    fn single_side_builds_match_paired_build_shape() {
        let (pcs, vcs) = {
            let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
            register_mixed(&mut b);
            b.build()
        };
        let pcs_only = {
            let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
            register_mixed(&mut b);
            b.build_prover()
        };
        let vcs_only = {
            let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
            register_mixed(&mut b);
            b.build_verifier()
        };

        assert_eq!(pcs.bodies.len(), 2);
        assert_eq!(vcs.bodies.len(), 2);
        assert_eq!(pcs_only.bodies.len(), pcs.bodies.len());
        assert_eq!(vcs_only.bodies.len(), vcs.bodies.len());

        // Single-side projection must pick the same arm per id as the
        // paired projection.
        for (paired, single) in pcs.bodies.iter().zip(&pcs_only.bodies) {
            assert_eq!(
                matches!(paired, ProverConstraint::Kernel(_)),
                matches!(single, ProverConstraint::Kernel(_)),
            );
        }
        for (paired, single) in vcs.bodies.iter().zip(&vcs_only.bodies) {
            assert_eq!(
                matches!(paired, VerifierConstraint::Kernel(_)),
                matches!(single, VerifierConstraint::Kernel(_)),
            );
        }
    }

    #[test]
    fn registration_path_picks_expected_arm_per_side() {
        let mut b = ConstraintsBuilder::<Gf2_64, Gf2>::new();
        b.add::<CarryChain>().unwrap(); // id 0: kernel on both sides
        add_and_gate(&mut b); // id 1: circuit on both sides
        let (pcs, vcs) = b.build();

        assert!(matches!(pcs.bodies[0], ProverConstraint::Kernel(_)));
        assert!(matches!(pcs.bodies[1], ProverConstraint::Circuit(_)));
        assert!(matches!(vcs.bodies[0], VerifierConstraint::Kernel(_)));
        assert!(matches!(vcs.bodies[1], VerifierConstraint::Circuit(_)));
    }
}
