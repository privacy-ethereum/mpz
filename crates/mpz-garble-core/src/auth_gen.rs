use crate::circuit::AuthEncryptedGate;
use mpz_circuits::{
    types::TypeError,
    Circuit, CircuitError, Gate
};
use mpz_core::{
    aes::FixedKeyAes,
    Block,
};
use mpz_memory_core::correlated::{Key, Mac};

use crate::fpre::{FpreGen, AuthBitShare, xor_auth_bit_share};

/// Errors that can occur during garbled circuit generation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum AuthGeneratorError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("generator not finished")]
    NotFinished,
}

/// Output of the generator.
#[derive(Debug)]
pub struct AuthGeneratorOutput {
    /// Output MACs of the circuit.
    pub outputs: Vec<Mac>,
}

/// Authenticated garbled circuit generator.
#[derive(Debug)]
pub struct AuthGenerator<'a> {
    /// The generator’s shares and delta from the function-independent Fpre phase.
    pub fpre: FpreGen,
    /// A buffer for storing 0-bit labels (or other data) during the garbling process.
    pub labels: Vec<Block>,
    /// A parallel buffer of AuthBitShares for each wire
    pub auth_bits: Vec<AuthBitShare>,
    /// The circuit to garble
    pub circ: &'a Circuit
}

impl<'a> AuthGenerator<'a> {
    /// Creates a new `AuthGenerator` from an [`FpreGen`](crate::fpre::FpreGen).
    ///
    /// The `buffer` is initialized empty to hold 0-bit labels or related data
    /// in subsequent protocol phases.
    pub fn new(circ: &'a Circuit, fpre: FpreGen) -> Self {
        Self {
            fpre,
            labels: Vec::new(),
            auth_bits: Vec::new(),
            circ
        }
    }

    /// Initializes the generator with the given inputs.
    pub fn initialize(
        &mut self,
        inputs: Vec<Block>,
    ) -> Result<(), AuthGeneratorError> {
        // 1) Expand self.buffer if needed, same as in the semi-honest code
        if self.circ.feed_count() > self.labels.len() {
            self.labels.resize(self.circ.feed_count(), Default::default());
        }

        if self.circ.feed_count() > self.auth_bits.len() {
            self.auth_bits.resize(self.circ.feed_count(), Default::default());
        }

        let mut count = 0;
        let mut inputs = inputs.into_iter();
        for input in self.circ.inputs() {
            for (node, label) in input.iter().zip(inputs.by_ref()) {
                self.labels[node.id()] = label;
                self.auth_bits[node.id()] = self.fpre.wire_shares[count].clone();
                count += 1;
            }
        }

        Ok(())
    }

    /// Phase 1: Evaluate all XOR and INV gates in-place, skipping AND gates.
    /// Updates `self.buffer` and `self.auth_bits`.
    pub fn evaluate_free_gates(&mut self) -> () {
        for gate in self.circ.gates() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let lx = self.labels[node_x.id()];
                    let ly = self.labels[node_y.id()];
                    self.labels[node_z.id()] = lx ^ ly;
                    
                    let sx = self.auth_bits[node_x.id()].clone();
                    let sy = self.auth_bits[node_y.id()].clone();
                    self.auth_bits[node_z.id()] = xor_auth_bit_share(&sx, &sy);
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let lx = self.labels[node_x.id()];
                    self.labels[node_z.id()] = lx ^ self.fpre.delta_a.as_block();

                    let sx = self.auth_bits[node_x.id()].clone();
                    self.auth_bits[node_z.id()] = sx;
                }
                Gate::And { .. } => {
                    // Skip for now
                }
            }
        }
    }

    /// Collect the generator's derandomization bits for AND gates. That is, for each AND gate,
    /// compute `(sx.bit() ^ triple.x.bit())` and `(sy.bit() ^ triple.y.bit())`.
    ///
    /// # Returns
    ///
    /// `(px_local, py_local)` as two `Vec<bool>` arrays, each indexed by the i-th AND gate in
    /// topological order.
    pub fn prepare_px_py(&mut self) -> (Vec<bool>, Vec<bool>) {
        let mut px_local = Vec::new();
        let mut py_local = Vec::new();
        let mut and_count = 0;

        // We iterate over each gate. For AND gates, we push the local bit into `px_local` or `py_local`.
        for gate in self.circ.gates() {
            match gate {
                Gate::And { x, y, .. } => {
                    // 1) The local share for x is `sx = self.auth_bits[x.id()]`
                    //    The triple share is `triple.x`.
                    let sx = self.auth_bits[x.id()].clone();
                    let sy = self.auth_bits[y.id()].clone();

                    // The triple for this AND gate presumably is at `self.fpre.triple_shares[and_count]`
                    // (assuming the triple_shares are in topological order)
                    let triple = &self.fpre.triple_shares[and_count];

                    // 2) Compute the local partial bits:
                    //    px_local[and_count] = (sx.bit() ^ triple.x.bit())
                    //    py_local[and_count] = (sy.bit() ^ triple.y.bit())
                    let px_bit = sx.bit() ^ triple.x.bit();
                    let py_bit = sy.bit() ^ triple.y.bit();

                    px_local.push(px_bit);
                    py_local.push(py_bit);

                    and_count += 1;
                }
                Gate::Xor { .. } | Gate::Inv { .. } => {
                    // do nothing
                }
            }
        }

        (px_local, py_local)
    }


    /// Phase 2: Handles all AND gates in the circuit, using derandomization bits `px_vec` and `py_vec`.
    /// Produces a list of `AuthEncryptedGate` that can be sent to the evaluator.
    ///
    /// # Arguments
    ///
    /// * `px_vec`, `py_vec` - Derandomization bits from evaluator.
    ///
    /// # Returns
    ///
    /// A `Vec<AuthEncryptedGate>` - one for each AND gate in the circuit, in topological order.
    pub fn garble_and_gates(
        &mut self,
        cipher: &FixedKeyAes,
        px_vec: &[bool],
        py_vec: &[bool],
    ) -> Result<Vec<AuthEncryptedGate>, AuthGeneratorError> {
        let mut and_gates = Vec::new();
        let mut and_count = 0;

        // ZDelta in EMP
        let mut zdelta_mask: Block = Block::ONES;
        zdelta_mask.set_lsb(false);
        let zdelta = self.fpre.delta_a.as_block() & zdelta_mask;

        for gate in self.circ.gates() {
            match gate {
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    // 1) Pull existing wire data
                    let lx = self.labels[node_x.id()];
                    let ly = self.labels[node_y.id()];
                    let sx = self.auth_bits[node_x.id()].clone();
                    let sy = self.auth_bits[node_y.id()].clone();

                    // 2) Grab the triple from preprocessed data
                    let triple = &mut self.fpre.triple_shares[and_count];
                    // triple.x, triple.y, triple.z are also AuthBitShare

                    // 3) Permutation bits lambda_a XOR lambda_alpha and lambda_b XOR lambda_beta
                    let px = px_vec[and_count]^(sx.bit()^triple.x.bit()); // a bool
                    let py = py_vec[and_count]^(sy.bit()^triple.y.bit()); // a bool

                    and_count += 1;

                    let mut sigma_mac = triple.z.mac;
                    let mut sigma_key = triple.z.key;

                    if px {
                        sigma_mac = sigma_mac + triple.y.mac;
                        sigma_key = sigma_key + triple.y.key;
                    }
                    if py {
                        sigma_mac = sigma_mac + triple.x.mac;
                        sigma_key = sigma_key + triple.x.key;
                    }

                    if px && py {
                        sigma_key = sigma_key + Key::from(zdelta); 
                    }

                    let z_mac = self.auth_bits[node_z.id()].mac; // existing mac for wire z
                    let z_key = self.auth_bits[node_z.id()].key; // existing key for wire z

                    let mut m = [Mac::default(); 4];
                    let mut k = [Key::default(); 4];

                    m[0] = sigma_mac + z_mac; 
                    m[1] = m[0] + sx.mac;
                    m[2] = m[0] + sy.mac;
                    m[3] = m[1] + sy.mac;

                    k[0] = sigma_key + z_key;
                    k[1] = k[0] + sx.key;
                    k[2] = k[0] + sy.key;
                    k[3] = k[1] + sy.key;
                    k[3] = k[3] + Key::from(zdelta);

                    // TODO: add tweaks for hashing

                    // Build an AuthEncryptedGate 
                    let mut auth_enc_gate = AuthEncryptedGate::new_with_labels(
                        lx, ly, 
                        self.fpre.delta_a.as_block().clone(), 
                        cipher
                    );

                    for j in 0..4 {
                        auth_enc_gate.0[j][0] ^= m[j].as_block();
                        auth_enc_gate.0[j][1] ^= k[j].as_block() ^ self.labels[node_z.id()];
                        if m[j].pointer() {
                            auth_enc_gate.0[j][1] ^= self.fpre.delta_a.as_block().clone();
                        }
                    }
                
                    and_gates.push(auth_enc_gate);

                    // let and_gate = AndGateTable::new(m, k);
                    // and_gates.push(and_gate);
                }
                Gate::Xor { .. } | Gate::Inv { .. } => { 
                    // do nothing 
                }
            }
        }

        Ok(and_gates)
    }

    /// Collect the MACs for each input wire of the circuit.
    pub fn collect_input_macs(&self) -> Vec<Mac> {
        let mut macs = Vec::new();
        for input in self.circ.inputs() {
            for node in input.iter() {
                macs.push(self.auth_bits[node.id()].mac);
            }
        }
        macs
    }

    /// Collect the input labels for the evaluator.
    pub fn collect_input_labels(&self, masked_inputs: Vec<bool>) -> Vec<Block> {
        let mut labels = Vec::new();
        let mut idx = 0;
        for input in self.circ.inputs() {
            for node in input.iter() {
                let mut label = self.labels[node.id()];
                if masked_inputs[idx] {
                    label = label ^ self.fpre.delta_a.as_block();
                }
                labels.push(label);
                idx += 1;
            }
        }
        labels
    }

    /// Collect the MACs for each output wire of the circuit.
    pub fn collect_output_macs(&self) -> AuthGeneratorOutput {
        // For each output "group" in the circuit, we iterate over its wires
        // and collect `auth_bits[node.id()].mac`.
        let outputs = self.circ
            .outputs()
            .iter()
            .flat_map(|output_wires| {
                output_wires.iter().map(move |node| {
                    // For each output wire node, return the MAC
                    self.auth_bits[node.id()].mac
                })
            })
            .collect();

        AuthGeneratorOutput { outputs }
    }
}

// Next steps:
// 1) Clean up with helper functions
// 2) Error handling
// 3) Input processing -- differentiate between Alice and Bob's inputs -- right now Bob picks all inputs
// 4) Output processing -- allow Alice to learn output as well, optimize by masking to sec param
// 5) Hash tweaks
