use mpz_memory_core::correlated::Mac;

use crate::circuit::{AuthEncryptedGate, sigma};
use mpz_circuits::{
    types:: TypeError,
    Circuit, CircuitError, Gate,
};
use mpz_core::{
    aes::FixedKeyAes,
    Block,
};


use mpz_memory_core::correlated:: Key;
use crate::fpre::{FpreEval, AuthBitShare, xor_auth_bit_share};
use crate::auth_gen::AuthGeneratorOutput;

/// Errors that can occur during garbled circuit evaluation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum AuthEvaluatorError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("evaluator not finished")]
    NotFinished,
    #[error("MAC verification failed at gate {0}")]
    MacCheckFailed(usize), 
}

/// Output of the evaluator.
#[derive(Debug)]
pub struct AuthEvaluatorOutput {
    /// Output MACs of the circuit.
    pub outputs: Vec<Mac>,
}

/// A table of MACs and keys for an AND gate.
#[derive(Debug, Clone)]
pub struct AndGateTable {
    /// MACs for the AND gate
    pub m: [Mac; 4],
    /// Keys for the AND gate
    pub k: [Key; 4],
}

impl AndGateTable {
    /// Add two `AndGateTable`s together.
    pub fn add(self, other: Self) -> Self {
        Self { 
            m: [
                self.m[0] + other.m[0], 
                self.m[1] + other.m[1], 
                self.m[2] + other.m[2], 
                self.m[3] + other.m[3]
            ], 
            k: [
                self.k[0] + other.k[0], 
                self.k[1] + other.k[1], 
                self.k[2] + other.k[2], 
                self.k[3] + other.k[3]
            ] 
        }
    }
}

impl AndGateTable {
    /// Creates a new `AndGateTable`
    pub fn new(m: [Mac; 4], k: [Key; 4]) -> Self {
        Self { m, k }
    }
}

/// Authenticated garbled circuit evaluator.
#[derive(Debug)]
pub struct AuthEvaluator<'a> {
    /// The evaluator's shares and delta from the function-independent Fpre phase.
    pub fpre: FpreEval,
    /// labels for evaluation
    pub labels: Vec<Block>,
    /// A parallel buffer of AuthBitShares for each wire
    pub auth_bits: Vec<AuthBitShare>,
    /// A parallel buffer of AuthBitShares for each wire
    pub masked_values: Vec<bool>,
    /// The circuit to garble
    pub circ: &'a Circuit
}

impl<'a> AuthEvaluator<'a> {
    /// Creates a new `AuthEvaluator` from an [`FpreEval`](crate::fpre::FpreEval) and circuit
    pub fn new(circ: &'a Circuit, fpre: FpreEval) -> Self {
        Self {
            fpre,
            labels: Vec::new(),
            auth_bits: Vec::new(),
            masked_values: Vec::new(),
            circ
        }
    }

    /// Initializes the evaluator's auth_bits with fpre.
    pub fn initialize(
        &mut self
    ) -> Result<(), AuthEvaluatorError> {
        let mut count = 0;
        if self.circ.feed_count() > self.auth_bits.len() {
            self.auth_bits.resize(self.circ.feed_count(), Default::default());
        }
        for input in self.circ.inputs() {
            for node in input.iter() {
                self.auth_bits[node.id()] = self.fpre.wire_shares[count].clone();
                count += 1;
            }
        }

        Ok(())
    }

    /// Phase 1: Garble all XOR and INV gates in-place, skipping AND gates.
    /// Updates `self.buffer` and `self.auth_bits`.
    pub fn garble_free_gates(&mut self) -> () {
        for gate in self.circ.gates() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    
                    let sx = self.auth_bits[node_x.id()].clone();
                    let sy = self.auth_bits[node_y.id()].clone();
                    self.auth_bits[node_z.id()] = xor_auth_bit_share(&sx, &sy);
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {

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
            if let Gate::And { x, y, .. } = gate {
                // 1) The local share for x is `sx = self.auth_bits[x.id()]`
                //    The triple share is `triple.x`.
                let sx = self.auth_bits[x.id()].clone();
                let sy = self.auth_bits[y.id()].clone();

                // The triple for this AND gate presumably is at `self.fpre.triple_shares[and_count]`
                // (assuming the triple_shares are in topological order)
                let triple = &self.fpre.triple_shares[and_count];

                // 2) Compute the local partial bits:
                let px_bit = sx.bit() ^ triple.x.bit();
                let py_bit = sy.bit() ^ triple.y.bit();

                px_local.push(px_bit);
                py_local.push(py_bit);

                and_count += 1;
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
        px_vec: &[bool],
        py_vec: &[bool],
    ) -> Result<Vec<AndGateTable>, AuthEvaluatorError> {
        let mut tables = Vec::new();
        let mut and_count = 0;

        // frpe->one in EMP
        let mut one: Block = Block::ZERO;
        one.set_lsb(true);

        for gate in self.circ.gates() {
            match gate {
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    // 1) Pull existing wire data
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
                    sigma_mac = sigma_mac + Mac::from(one); 
                }

                let z_mac = self.auth_bits[node_z.id()].mac; // existing mac for wire z
                let z_key = self.auth_bits[node_z.id()].key; // existing key for wire z

                let mut m = [Mac::default(); 4];
                let mut k = [Key::default(); 4];

                m[0] = sigma_mac + z_mac; 
                m[1] = m[0] + sx.mac;
                m[2] = m[0] + sy.mac;
                m[3] = m[1] + sy.mac;
                m[3] = m[3] + Mac::from(one);

                k[0] = sigma_key + z_key;
                k[1] = k[0] + sx.key;
                k[2] = k[0] + sy.key;
                k[3] = k[1] + sy.key;

                tables.push(AndGateTable { m, k });

                }
                Gate::Xor { .. } | Gate::Inv { .. } => { 
                    // do nothing 
                }
            }
        }

        Ok(tables)
    }

    /// Verify MACs and send the masked inputs to the generator.
    pub fn collect_masked_inputs(&mut self, inputs: Vec<bool>, input_macs: Vec<Mac>) -> Result<Vec<bool>, AuthEvaluatorError> {
        let mut masked_inputs = Vec::new();
        let mut idx = 0;
        for input in self.circ.inputs() {
            for node in input.iter() {
                let mut mac = input_macs[idx].as_block().clone(); // Access input_macs normally
                let key = self.auth_bits[node.id()].key.as_block().clone(); // Access auth_bits using node.id()
                
                let mac_lsb = mac.lsb();

                if mac_lsb {
                    mac = mac ^ self.fpre.delta_b.as_block();
                }

                if key != mac {
                    return Err(AuthEvaluatorError::MacCheckFailed(idx));
                }
                masked_inputs.push(self.auth_bits[node.id()].bit()^inputs[idx]^mac_lsb);
                idx += 1;
            }
        }

        if self.circ.feed_count() > self.masked_values.len() {
            self.masked_values.resize(self.circ.feed_count(), Default::default());
        }

        let mut masked_iter = masked_inputs.iter().copied();  // Create an iterator over references
        for input in self.circ.inputs() {
            for (node, masked_value) in input.iter().zip(masked_iter.by_ref()) {
                self.masked_values[node.id()] = masked_value;
            }
        }

        Ok(masked_inputs) 
    }

    /// Set the input labels for the evaluator.
    pub fn set_input_labels(&mut self, input_labels: Vec<Block>) -> () {
        let mut idx = 0;
        if self.circ.feed_count() > self.labels.len() {
            self.labels.resize(self.circ.feed_count(), Default::default());
        }
        for node in self.circ.inputs().iter() {
            for node in node.iter() {
                self.labels[node.id()] = input_labels[idx];
                idx += 1;
            }
        }
    }

    /// Evaluates all gates in the circuit, using the tables and gates for AND gates.
    pub fn evaluate(&mut self, tables: Vec<AndGateTable>, gates: Vec<AuthEncryptedGate>, cipher: &FixedKeyAes) ->  Result<(), AuthEvaluatorError> {
        let mut and_count = 0;

        // For each gate in the circuit
        for gate in self.circ.gates() {
            match gate {
                Gate::Xor { x, y, z } => {                    
                    self.labels[z.id()] = self.labels[x.id()] ^ self.labels[y.id()];
                    self.masked_values[z.id()] = self.masked_values[x.id()] ^ self.masked_values[y.id()];
                }
                Gate::Inv { x, z } => {                    
                    self.labels[z.id()] = self.labels[x.id()];
                    self.masked_values[z.id()] = !self.masked_values[x.id()];
                }
                Gate::And { x, y, z } => {
                    // 1) compute which row => index = 2 * mask[x] + mask[y]
                    let bit_x = self.masked_values[x.id()] as usize;
                    let bit_y = self.masked_values[y.id()] as usize;
                    let index = 2*bit_x + bit_y;

                    // 3) Weird hashing logic from EMP
                    let lx = self.labels[x.id()];
                    let ly = self.labels[y.id()];
                    
                    let a = sigma(lx, cipher);
                    let b = sigma(sigma(ly, cipher), cipher);

                    let mut h = [Block::default(); 2];
                    h[0] = a ^ b;
                    h[1] = h[0];

                    let delta = self.fpre.delta_b.as_block().clone();

                    let gate_mac: Block = gates[and_count].0[index][0].clone()^h[0];
                    let gate_key: Block = gates[and_count].0[index][1].clone()^h[1];

                    let table_mac: Block = tables[and_count].m[index].as_block().clone();
                    let table_key: Block = tables[and_count].k[index].as_block().clone();

                    if gate_mac == table_key {
                        self.masked_values[z.id()] = false;
                    }
                    else if gate_mac == table_key^delta {
                        self.masked_values[z.id()] = true;
                    }
                    else {
                        return Err(AuthEvaluatorError::MacCheckFailed(and_count));
                    }
                    self.masked_values[z.id()] = self.masked_values[z.id()] ^ table_mac.lsb();
                    self.labels[z.id()] = gate_key^table_mac;
                    and_count += 1;
                }
            }
        }
        Ok(())
    }

    /// Takes the generator's `AuthGeneratorOutput { outputs }`,
    /// one MAC per output wire, and checks each against the evaluator's local data.
    ///
    /// If the check succeeds, we produce a final `Vec<bool>` of the circuit's outputs.
    /// If something mismatches, we return an error (e.g. `MacCheckFailed`).
    pub fn finalize_outputs(
        &mut self,
        gen_output: AuthGeneratorOutput,
    ) -> Result<Vec<bool>, AuthEvaluatorError> {

        // 1) Collect *all* output wire IDs in a single linear order
        let output_wire_ids: Vec<usize> = self.circ
            .outputs()
            .iter()
            .flat_map(|output_wires| {
                output_wires.iter().map(|node| node.id())
            })
            .collect();

        // 2) Ensure the generator's output count matches
        if output_wire_ids.len() != gen_output.outputs.len() {
            return Err(AuthEvaluatorError::CircuitError(
                mpz_circuits::CircuitError::InvalidInputCount(
                    gen_output.outputs.len(),
                    output_wire_ids.len(),
                ),
            ));
        }

        // 3) We'll build final bits by zipping each wire ID with the generator's MAC
        //    then verifying them in a closure. We use `.map(...) -> Result<bool, _>` and
        //    finally `.collect()` to gather them into `Result<Vec<bool>, _>`.
        let final_bits: Result<Vec<bool>, AuthEvaluatorError> = output_wire_ids
            .iter()
            .enumerate()
            .map(|(i, &wire_id)| {
                // If the MAC's LSB is 1, we XOR with delta_b to clear that pointer bit
            
                let mut mac = gen_output.outputs[i].as_block().clone();
                if mac.lsb() {
                    mac = mac ^ self.fpre.delta_b.as_block();
                }

                // Compare with the local key
                let key = self.auth_bits[wire_id].key.as_block().clone();
                if key != mac {
                    return Err(AuthEvaluatorError::MacCheckFailed(i));
                }

                // Derive the final bit from:
                //   * self.masked_values[wire_id]
                //   * local share bit: self.auth_bits[wire_id].bit()
                //   * generator's pointer: gen_output.outputs[i].pointer()
                let bit = self.masked_values[wire_id]
                    ^ self.auth_bits[wire_id].bit()
                    ^ gen_output.outputs[i].pointer();

                Ok(bit)
            })
            .collect();

        // Return the collected bits or the first error
        final_bits
    }

}

