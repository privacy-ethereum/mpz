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
use crate::fpre::{FpreEval, AuthBitShare};

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
    #[error("expected {expected} auth bits, got {actual}")]
    InvalidAuthBitCount { expected: usize, actual: usize },
    #[error("expected {expected} AND gates, got {actual}")]
    InvalidPxPyCount { expected: usize, actual: usize },
    #[error("expected {expected} input MACs, got {actual}")]
    InvalidInputMacCount { expected: usize, actual: usize },
    #[error("expected {expected} output MACs, got {actual}")]
    InvalidOutputMacCount { expected: usize, actual: usize },
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

/// Performs the gate "hashing" step for evaluator.
/// Returns `(gate_mac, gate_key)`.
fn gate_eval(
    lx: Block,
    ly: Block,
    cipher: &FixedKeyAes,
    enc_gate: AuthEncryptedGate,
    index: usize,
) -> (Block, Block) {
    // 1) Evaluate sigma(...) on x and y
    let a = sigma(lx, cipher);
    let b = sigma(sigma(ly, cipher), cipher);

    // 2) Combine them into h
    let mut h = [Block::default(); 2];
    h[0] = a ^ b;
    h[1] = h[0];

    // 3) Merge with the row data from `enc_gate`
    let gate_mac = enc_gate.0[index][0] ^ h[0];
    let gate_key = enc_gate.0[index][1] ^ h[1];

    (gate_mac, gate_key)
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

    /// Initializes wire shares for the evaluator’s input wires.
    pub fn initialize(
        &mut self
    ) -> Result<(), AuthEvaluatorError> {

        if self.circ.input_len() + self.circ.and_count() != self.fpre.wire_shares.len() {
            return Err(AuthEvaluatorError::InvalidAuthBitCount {
                expected: self.circ.input_len() + self.circ.and_count(),
                actual: self.fpre.wire_shares.len(),
            });
        }

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

        // Fill auth bits for output wires of AND gates as well
        for gate in self.circ.gates() {
            if let Gate::And { x: _, y: _, z } = gate {
                self.auth_bits[z.id()] = self.fpre.wire_shares[count].clone();
                count += 1;
            }
        }

        Ok(())
    }

    /// Handles free gates (XOR/NOT), skipping AND gates.
    pub fn garble_free_gates(&mut self) {
        for gate in self.circ.gates() {
            match gate {
                Gate::Xor { x, y, z } => {
                    let sx = self.auth_bits[x.id()];
                    let sy = self.auth_bits[y.id()];
                    self.auth_bits[z.id()] = sx+sy;
                }
                Gate::Inv { x, z } => {
                    let sx = self.auth_bits[x.id()];
                    self.auth_bits[z.id()] = sx;
                }
                Gate::And { .. } => {}
            }
        }
    }

    /// Produces `(px, py)` derandomization bits for each AND gate,
    /// based on the auth bit and triple from `fpre.triple_shares`.
    pub fn prepare_px_py(&mut self) -> (Vec<bool>, Vec<bool>) {
        let mut px = Vec::new();
        let mut py = Vec::new();
        let mut and_count = 0;

        for gate in self.circ.gates() {
            if let Gate::And { x, y, .. } = gate {
                let sx = self.auth_bits[x.id()].clone();
                let sy = self.auth_bits[y.id()].clone();
                let triple = &self.fpre.triple_shares[and_count];
                px.push(sx.bit() ^ triple.x.bit());
                py.push(sy.bit() ^ triple.y.bit());
                and_count += 1;
            }
        }
        (px, py)
    }

    /// Produces partial AND gate tables for evaluator.
    pub fn garble_and_gates(
        &mut self,
        px_vec: Vec<bool>,
        py_vec: Vec<bool>,
    ) -> Result<Vec<AndGateTable>, AuthEvaluatorError> {


        if px_vec.len() != self.circ.and_count() || py_vec.len() != self.circ.and_count() {
            return Err(AuthEvaluatorError::InvalidPxPyCount {
                expected: self.circ.and_count(),
                actual: px_vec.len().min(py_vec.len()),
            });
        }

        let mut tables = Vec::new();
        let mut and_count = 0;

        let mut one: Block = Block::ZERO;
        one.set_lsb(true);

        for gate in self.circ.gates() {
            if let Gate::And { x, y, z } = gate {
                let sx = self.auth_bits[x.id()];
                let sy = self.auth_bits[y.id()];

                let triple = &mut self.fpre.triple_shares[and_count];

                let mut px = sx.bit()^triple.x.bit();
                let mut py = sy.bit()^triple.y.bit();

                px ^= px_vec[and_count];
                py ^= py_vec[and_count];

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

                let z_mac = self.auth_bits[z.id()].mac; // existing mac for wire z
                let z_key = self.auth_bits[z.id()].key; // existing key for wire z

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

                tables.push(AndGateTable::new(m, k));

            }
        }

        Ok(tables)
    }

    /// Verifies input MACs, returning `masked_inputs`.
    pub fn collect_masked_inputs(&mut self, inputs: Vec<bool>, input_macs: Vec<Mac>) -> Result<Vec<bool>, AuthEvaluatorError> {
        let total_inputs = self.circ.input_len();
        if input_macs.len() != total_inputs || inputs.len() != total_inputs {
            return Err(AuthEvaluatorError::InvalidInputMacCount {
                expected: total_inputs,
                actual: input_macs.len().min(inputs.len()),
            });
        }

        let mut masked_inputs = Vec::new();
        let mut idx = 0;
        for input in self.circ.inputs() {
            for node in input.iter() {
                let delta_b = self.fpre.delta_b.into_inner();
                let mut mac = input_macs[idx].as_block().clone(); 
                let key = self.auth_bits[node.id()].key.as_block().clone();
                
                let mac_lsb = mac.lsb();

                if mac_lsb {
                    mac = mac ^ delta_b;
                }

                if key != mac {
                    return Err(AuthEvaluatorError::MacCheckFailed(idx));
                }

                let masked_input = self.auth_bits[node.id()].bit()^inputs[idx]^mac_lsb;
                masked_inputs.push(masked_input);
                idx += 1;
            }
        }

        // Put them into self.masked_values
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
        let delta_b = self.fpre.delta_b.into_inner();

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
                    // compute which row to decrypt
                    let bx = self.masked_values[x.id()] as usize;
                    let by = self.masked_values[y.id()] as usize;
                    let index = 2*bx + by;

                    // compute `(gate_mac, gate_key)`
                    let (gate_mac, gate_key) = gate_eval(
                        self.labels[x.id()],
                        self.labels[y.id()],
                        cipher,
                        gates[and_count],
                        index,
                    );

                    let table_mac: Block = tables[and_count].m[index].as_block().clone();
                    let table_key: Block = tables[and_count].k[index].as_block().clone();

                    if gate_mac == table_key {
                        self.masked_values[z.id()] = false;
                    }
                    else if gate_mac == table_key^delta_b {
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

    /// Verifies MAC of gen's share and reconstructs output bits. 
    pub fn finalize_outputs(
        &mut self,
        gen_output_macs: Vec<Mac>,
    ) -> Result<Vec<bool>, AuthEvaluatorError> {

        let delta_b = self.fpre.delta_b.into_inner();

        let wire_ids = self.circ
            .outputs()
            .iter()
            .flat_map(|group| group.iter().map(|node| node.id()))
            .collect::<Vec<_>>();

        if gen_output_macs.len() != self.circ.output_len() {
            return Err(AuthEvaluatorError::InvalidOutputMacCount {
                expected: self.circ.output_len(),
                actual: gen_output_macs.len(),
            });
        }

        let final_bits = wire_ids.iter().enumerate()
            .map(|(i, &wid)| {
                let mut mac = gen_output_macs[i].as_block().clone();
                if mac.lsb() {
                    mac ^= delta_b;
                }
                let key = self.auth_bits[wid].key.as_block().clone();
                if key != mac {
                    return Err(AuthEvaluatorError::MacCheckFailed(i));
                }
                let bit = self.masked_values[wid]
                    ^ self.auth_bits[wid].bit()
                    ^ gen_output_macs[i].pointer();
                Ok(bit)
            })
            .collect::<Result<Vec<_>,_>>()?;

        Ok(final_bits)
    }
}

