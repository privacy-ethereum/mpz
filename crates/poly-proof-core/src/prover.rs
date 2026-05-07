//! Prover-side logic for the QuickSilver polynomial proof.

use rand_chacha::{
    ChaCha12Rng,
    rand_core::{RngCore, SeedableRng},
};
use zerocopy::IntoBytes;

use crate::{
    ExtensionField, Field, ProofMessage, ProverVope,
    circuit::{Circuit, CircuitNode},
};

/// Prover for the QuickSilver polynomial proof.
#[derive(Clone)]
pub struct Prover<E: Field> {
    /// The constraint circuits, indexed by `poly_id`.
    circuits: Vec<Circuit<E>>,
    /// Scratch-buffer layout for each circuit, parallel to `circuits`.
    layouts: Vec<CircuitLayout>,
    /// Shared scratch buffer for circuit evaluation, sized for the largest
    /// circuit.
    scratch: Vec<E>,
    /// Maximum polynomial degree across all circuits.
    d_max: usize,
    /// Running coefficient accumulator (χ-weighted).
    ///
    /// Length `d_max` (degrees 0 through `d_max - 1`; the highest-degree
    /// coefficient is not sent).
    accumulators: Vec<E>,
}

impl<E: Field> Prover<E> {
    /// Create a new prover with the given constraint circuits.
    pub fn new(circuits: Vec<Circuit<E>>) -> Self {
        let d_max = circuits.iter().map(|c| c.degree()).max().unwrap_or(0);
        let layouts: Vec<CircuitLayout> =
            circuits.iter().map(CircuitLayout::from_circuit).collect();
        let max_scratch = layouts.iter().map(|l| l.scratch_size).max().unwrap_or(0);

        Self {
            circuits,
            layouts,
            scratch: vec![E::zero(); max_scratch],
            d_max,
            accumulators: vec![E::zero(); d_max],
        }
    }

    /// Accumulate a batch of polynomial evaluations under a `seed`.
    /// 
    /// Each evaluation is a `(poly_id, macs, values)` triple: the
    /// circuit to evaluate, one MAC per variable, and one witness
    /// value per variable.
    ///
    /// `seed` must be bound to a Fiat-Shamir transcript covering all
    /// witness commitments preceding the call.
    pub fn accumulate<W: Field>(
        &mut self,
        evaluations: &[(usize, &[E], &[W])],
        seed: [u8; 32],
    ) -> Result<(), ProverError>
    where
        E: ExtensionField<W> + IntoBytes + zerocopy::FromBytes,
    {
        // Bulk-fill independent χ values from the keystream.
        let mut chis = vec![<E as Field>::zero(); evaluations.len()];
        let mut rng = ChaCha12Rng::from_seed(seed);
        rng.fill_bytes(chis.as_mut_slice().as_mut_bytes());

        for (&(poly_id, macs, values), &chi) in evaluations.iter().zip(chis.iter()) {
            self.evaluate_circuit(poly_id, macs, values, chi)?;
        }
        Ok(())
    }

    /// Apply VOPE mask and produce the final proof message.
    pub fn finalize(mut self, vope: &ProverVope<E>) -> Result<ProofMessage<E>, ProverError> {
        if vope.coeffs.len() != self.d_max {
            return Err(ErrorRepr::VopeLength {
                expected: self.d_max,
                actual: vope.coeffs.len(),
            }
            .into());
        }

        for h in 0..self.d_max {
            self.accumulators[h] = self.accumulators[h] + vope.coeffs[h];
        }

        Ok(ProofMessage {
            coefficients: self.accumulators,
        })
    }

    /// Walk circuit `poly_id` bottom-up on `macs` and `values`, computing
    /// coefficient vectors at each node, then accumulate the output into
    /// the running accumulator with degree-shift and χ-scaling by `chi_power`.
    fn evaluate_circuit<W: Field>(
        &mut self,
        poly_id: usize,
        macs: &[E],
        values: &[W],
        chi_power: E,
    ) -> Result<(), ProverError>
    where
        E: ExtensionField<W>,
    {
        if poly_id >= self.circuits.len() {
            return Err(ErrorRepr::UnknownPolyId {
                poly_id,
                count: self.circuits.len(),
            }
            .into());
        }
        let circuit = &self.circuits[poly_id];
        let n_vars = circuit.num_vars();
        if macs.len() != n_vars {
            return Err(ErrorRepr::MacCount {
                poly_id,
                expected: n_vars,
                actual: macs.len(),
            }
            .into());
        }
        if values.len() != n_vars {
            return Err(ErrorRepr::ValueCount {
                poly_id,
                expected: n_vars,
                actual: values.len(),
            }
            .into());
        }
        let layout = &self.layouts[poly_id];
        let scratch = &mut self.scratch;

        for ((node, &offset), &out_deg) in circuit
            .nodes
            .iter()
            .zip(&layout.node_offsets)
            .zip(&circuit.node_degrees)
        {
            match *node {
                CircuitNode::Var(idx) => {
                    scratch[offset] = macs[idx];
                    scratch[offset + 1] = E::embed(values[idx]);
                }
                CircuitNode::Const(c) => {
                    scratch[offset] = c;
                }
                CircuitNode::Mul(a, b) => {
                    // Var nodes are always degree-1 polynomials with two
                    // coefficients: [mac, embed(w)]. The arms below exploit
                    // this structure to keep witness terms in the subfield
                    // until they have to enter the extension field.
                    match (circuit.nodes[a], circuit.nodes[b]) {
                        // Variable × variable
                        (CircuitNode::Var(a_idx), CircuitNode::Var(b_idx)) => {
                            // (mac_a + w_a·Δ)(mac_b + w_b·Δ) expanded by degree:
                            //   slot 0 (Δ⁰): mac_a · mac_b
                            //   slot 1 (Δ¹): w_b · mac_a + w_a · mac_b
                            //   slot 2 (Δ²): w_a · w_b
                            let a_mac = macs[a_idx];
                            let a_w = values[a_idx];
                            let b_mac = macs[b_idx];
                            let b_w = values[b_idx];
                            scratch[offset] = a_mac * b_mac;
                            scratch[offset + 1] = E::embed(b_w) * a_mac + E::embed(a_w) * b_mac;
                            scratch[offset + 2] = E::embed(a_w * b_w);
                        }
                        // Variable × coefficient vector (either operand may
                        // be the Var; we pick out which and use one loop body)
                        (CircuitNode::Var(v), _) | (_, CircuitNode::Var(v)) => {
                            let (var_idx, other) =
                                if matches!(circuit.nodes[a], CircuitNode::Var(_)) {
                                    (v, b)
                                } else {
                                    (v, a)
                                };
                            let out_len = out_deg + 1;
                            for k in 0..out_len {
                                scratch[offset + k] = E::zero();
                            }
                            let v_mac = macs[var_idx];
                            let v_w_embed = E::embed(values[var_idx]);
                            let e_off = layout.node_offsets[other];
                            let e_len = circuit.node_degrees[other] + 1;
                            for i in 0..e_len {
                                let coeff = scratch[e_off + i];
                                scratch[offset + i] = scratch[offset + i] + coeff * v_mac;
                                scratch[offset + i + 1] =
                                    scratch[offset + i + 1] + v_w_embed * coeff;
                            }
                        }
                        // Coefficient vector × coefficient vector (general convolution)
                        _ => {
                            let out_len = out_deg + 1;
                            for k in 0..out_len {
                                scratch[offset + k] = E::zero();
                            }
                            let a_off = layout.node_offsets[a];
                            let a_len = circuit.node_degrees[a] + 1;
                            let b_off = layout.node_offsets[b];
                            let b_len = circuit.node_degrees[b] + 1;
                            for ai in 0..a_len {
                                let a_val = scratch[a_off + ai];
                                for bi in 0..b_len {
                                    scratch[offset + ai + bi] =
                                        scratch[offset + ai + bi] + a_val * scratch[b_off + bi];
                                }
                            }
                        }
                    }
                }
                // Negate every coefficient of the operand.
                CircuitNode::Neg(a) => {
                    let len = out_deg + 1;
                    let a_off = layout.node_offsets[a];
                    for k in 0..len {
                        scratch[offset + k] = -scratch[a_off + k];
                    }
                }
                // Add two coefficient vectors. The lower-degree operand
                // is degree-shifted to match the higher-degree one.
                CircuitNode::Add(a, b) => {
                    let out_len = out_deg + 1;
                    let out_end = offset + out_len;
                    let a_len = circuit.node_degrees[a] + 1;
                    let a_end = layout.node_offsets[a] + a_len;
                    let b_len = circuit.node_degrees[b] + 1;
                    let b_end = layout.node_offsets[b] + b_len;

                    for k in 0..out_len {
                        scratch[offset + k] = E::zero();
                    }
                    for k in 0..a_len {
                        scratch[out_end - 1 - k] = scratch[a_end - 1 - k];
                    }
                    for k in 0..b_len {
                        scratch[out_end - 1 - k] =
                            scratch[out_end - 1 - k] + scratch[b_end - 1 - k];
                    }
                }
            }
        }

        // Skip the highest-degree coefficient.
        let out_end = layout.node_offsets[circuit.output] + circuit.degree();

        // Degree-shift the output into the accumulator, aligning
        // lower-degree outputs to match d_max.
        for k in 0..circuit.degree() {
            self.accumulators[self.d_max - 1 - k] =
                self.accumulators[self.d_max - 1 - k] + scratch[out_end - 1 - k] * chi_power;
        }
        Ok(())
    }

    /// Number of VOPEs the caller must prepare for
    /// [`finalize`](Prover::finalize).
    pub fn required_vopes(&self) -> usize {
        // d+1 coefficients, minus the highest-degree one (not sent) = d.
        self.d_max
    }

}

/// Scratch-buffer layout for one circuit.
///
/// Each node produces an intermediate polynomial in Δ; this layout assigns
/// each node a contiguous range of slots (one slot per coefficient) in a flat
/// scratch array.
#[derive(Clone)]
struct CircuitLayout {
    /// Scratch offset for each node, indexed by `NodeId` (parallel to
    /// [`Circuit::nodes`]).
    node_offsets: Vec<usize>,
    /// Total scratch slots needed for this circuit.
    scratch_size: usize,
}

impl CircuitLayout {
    fn from_circuit<E: Field>(circuit: &Circuit<E>) -> Self {
        let mut node_offsets = vec![0usize; circuit.nodes.len()];
        let mut offset = 0;
        for (i, &deg) in circuit.node_degrees.iter().enumerate() {
            node_offsets[i] = offset;
            offset += deg + 1;
        }
        Self {
            node_offsets,
            scratch_size: offset,
        }
    }
}

/// Prover error.
#[derive(Debug, thiserror::Error)]
#[error("prover error: {0}")]
pub struct ProverError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("incorrect VOPE length: expected {expected}, got {actual}")]
    VopeLength { expected: usize, actual: usize },
    #[error("unknown poly_id: {poly_id} (only {count} circuits registered)")]
    UnknownPolyId { poly_id: usize, count: usize },
    #[error("wrong number of MACs for poly_id {poly_id}: expected {expected}, got {actual}")]
    MacCount {
        poly_id: usize,
        expected: usize,
        actual: usize,
    },
    #[error("wrong number of values for poly_id {poly_id}: expected {expected}, got {actual}")]
    ValueCount {
        poly_id: usize,
        expected: usize,
        actual: usize,
    },
}
