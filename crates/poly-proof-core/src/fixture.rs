use mpz_circuits_new::fixtures::{
    acc_mux, addr_base_mux, addr_index_mux, carry_chain, carry_generate, fp_mux,
    mul_bit_extraction, mul_force, pc_mux, sp_mux, write_back, write_back_bit0,
};

use crate::{ConstraintId, ConstraintsBuilder, Field, circuit::BuildError};

/// Step-circuit constraint set added to a builder.
pub struct StepConstraints {
    /// `ids[i]` is the [`ConstraintId`] of template `i`.
    pub ids: Vec<ConstraintId>,
    /// `counts[i]` is how many times template `i` is instantiated per step.
    pub counts: Vec<usize>,
}

/// Add the 12 step-circuit constraint templates to `b` and return
/// their [`ConstraintId`]s alongside per-template instantiation counts.
pub fn add_step_constraints<E: Field>(
    b: &mut ConstraintsBuilder<E>,
) -> Result<StepConstraints, BuildError> {
    let ids = vec![
        b.add(carry_generate)?,     // 0
        b.add(carry_chain)?,        // 1
        b.add(write_back)?,         // 2
        b.add(write_back_bit0)?,    // 3
        b.add(addr_base_mux)?,      // 4
        b.add(addr_index_mux)?,     // 5
        b.add(mul_bit_extraction)?, // 6
        b.add(mul_force)?,          // 7
        b.add(acc_mux)?,            // 8
        b.add(pc_mux)?,             // 9
        b.add(sp_mux)?,             // 10
        b.add(fp_mux)?,             // 11
    ];

    let counts = vec![
        32, // carry generate
        32, // carry chain
        31, // write-back i>0
        1,  // write-back i=0
        20, // addr base mux (2 slots x 10 bits)
        32, // addr index mux (2 slots x 16 bits)
        1,  // MUL bit extraction (5-level binary tree)
        1,  // MUL force
        32, // acc' MUX
        20, // PC' MUX (~16 bits + carry)
        12, // SP' MUX (~10 bits + carry)
        18, // FP' MUX
    ];

    Ok(StepConstraints { ids, counts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Constraints;
    use mpz_fields::gf2_64::Gf2_64;

    #[test]
    fn test_fixture_stats() {
        let mut b = Constraints::<Gf2_64>::builder();
        let step = add_step_constraints(&mut b).expect("fixtures must compile");
        let constraints = b.build();

        assert_eq!(step.ids.len(), 12);
        assert_eq!(step.counts.len(), 12);

        let expected: Vec<(usize, usize)> = vec![
            // (degree, mul_count)
            (3, 2),  // carry generate
            (2, 1),  // carry chain
            (6, 5),  // write-back i>0
            (6, 5),  // write-back i=0
            (3, 3),  // addr base mux
            (2, 1),  // addr index mux
            (6, 31), // MUL bit extraction tree
            (2, 1),  // MUL force
            (3, 2),  // acc' MUX
            (4, 4),  // PC' MUX
            (3, 2),  // SP' MUX
            (2, 1),  // FP' MUX
        ];

        for (i, (exp_deg, exp_muls)) in expected.iter().enumerate() {
            let circ = &constraints.circuits[i];
            assert_eq!(circ.degree(), *exp_deg, "template {i}: degree mismatch");
            assert_eq!(
                circ.mul_count(),
                *exp_muls,
                "template {i}: mul count mismatch"
            );
        }

        // Total instantiations: 232.
        let total: usize = step.counts.iter().sum();
        assert_eq!(total, 232);
    }
}
