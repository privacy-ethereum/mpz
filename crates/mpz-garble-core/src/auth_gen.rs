use crate::{
    circuit::AuthEncryptedGate,
    fpre::{FpreGen, AuthBitShare},
};
use mpz_circuits::{
    types::TypeError,
    Circuit, Gate, CircuitError
};
use mpz_core::{
    aes::FixedKeyAes,
    Block,
};
use mpz_memory_core::correlated::{Key, Mac};

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

/// Authenticated garbled circuit generator.
#[derive(Debug)]
pub struct AuthGenerator<'a> {
    /// Generator's share of Fpre data.
    pub fpre: FpreGen,
    /// 0-bit labels for each wire in the circuit.
    pub labels: Vec<Block>,
    /// Authenticated bit shares for each wire.
    pub auth_bits: Vec<AuthBitShare>,
    /// Reference to the circuit to be garbled.
    pub circ: &'a Circuit,
}

impl<'a> AuthGenerator<'a> {
    /// Creates a new `AuthGenerator` from FpreGen and circuit.
    pub fn new(circ: &'a Circuit, fpre: FpreGen) -> Self {
        Self {
            fpre,
            labels: Vec::new(),
            auth_bits: Vec::new(),
            circ
        }
    }

    /// Assigns the provided `zero_labels` to the wire labels for the circuit's input wires,
    /// and stores the corresponding `auth_bits` from `fpre.wire_shares`.
    pub fn initialize(
        &mut self,
        zero_labels: Vec<Block>,
    ) -> Result<(), AuthGeneratorError> {
        if self.circ.feed_count() > self.labels.len() {
            self.labels.resize(self.circ.feed_count(), Default::default());
        }

        if self.circ.feed_count() > self.auth_bits.len() {
            self.auth_bits.resize(self.circ.feed_count(), Default::default());
        }

        let mut count = 0;
        let mut zero_labels_iter = zero_labels.into_iter();
        for input in self.circ.inputs() {
            for (node, label) in input.iter().zip(zero_labels_iter.by_ref()) {
                self.labels[node.id()] = label;
                self.auth_bits[node.id()] = self.fpre.wire_shares[count].clone();
                count += 1;
            }
        }

        Ok(())
    }

    /// Evaluates all XOR and INV gates (free gates), skipping AND gates.
    /// - XOR gate => XOR the wire labels & the `auth_bits`.
    /// - INV gate => label ^= delta_a, bit shares are cloned.
    pub fn evaluate_free_gates(&mut self) -> () {
        let delta_a = self.fpre.delta_a.into_inner();
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
                    
                    let sx = self.auth_bits[node_x.id()];
                    let sy = self.auth_bits[node_y.id()];
                    self.auth_bits[node_z.id()] = sx + sy;
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let lx = self.labels[node_x.id()];
                    self.labels[node_z.id()] = lx ^ delta_a;

                    let sx = self.auth_bits[node_x.id()];
                    self.auth_bits[node_z.id()] = sx;
                }
                Gate::And { .. } => {
                    // Skip for now
                }
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


    /// Generates an `AuthEncryptedGate` for each AND gate, using the given
    /// `(px_vec, py_vec)` derandomization bits from the evaluator.
    pub fn garble_and_gates(
        &mut self,
        cipher: &FixedKeyAes,
        px_vec: Vec<bool>,
        py_vec: Vec<bool>,
    ) -> Result<Vec<AuthEncryptedGate>, AuthGeneratorError> {
        let mut and_gates = Vec::new();
        let mut and_count = 0;

        // Delta with lsb set to 0 to not flip the pointer bit
        let mut zdelta_mask: Block = Block::ONES;
        zdelta_mask.set_lsb(false);
        let zdelta = self.fpre.delta_a.as_block() & zdelta_mask;

        for gate in self.circ.gates() {
            if let Gate::And { x, y, z } = gate {

                    let lx = self.labels[x.id()];
                    let ly = self.labels[y.id()];

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
                        sigma_key = sigma_key + Key::from(zdelta); 
                    }

                    let z_mac = self.auth_bits[z.id()].mac; // existing mac for wire z
                    let z_key = self.auth_bits[z.id()].key; // existing key for wire z

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

                    let mut enc_gate = AuthEncryptedGate::new_with_labels(
                        lx,
                        ly,
                        self.fpre.delta_a.as_block().clone(),
                        cipher,
                    );

                    for j in 0..4 {
                        enc_gate.0[j][0] ^= m[j].as_block();
                        enc_gate.0[j][1] ^= k[j].as_block() ^ self.labels[z.id()];
                        if m[j].pointer() {
                            enc_gate.0[j][1] ^= self.fpre.delta_a.as_block().clone();
                        }
                    }
                
                    and_gates.push(enc_gate);
            }
        }

        Ok(and_gates)
    }

    /// Returns the MAC for each input wire.
    pub fn collect_input_macs(&self) -> Vec<Mac> {
        let mut macs = Vec::new();
        for input in self.circ.inputs() {
            for node in input.iter() {
                macs.push(self.auth_bits[node.id()].mac);
            }
        }
        macs
    }

    /// Collect the input labels corresponding to masked_inputsfor the evaluator.
    pub fn collect_input_labels(&self, masked_inputs: Vec<bool>) -> Vec<Block> {
        let mut labels = Vec::new();
        let mut idx = 0;
        let delta_a = self.fpre.delta_a.into_inner();
        for input in self.circ.inputs() {
            for node in input.iter() {
                let mut label = self.labels[node.id()];
                if masked_inputs[idx] {
                    label = label ^ delta_a;
                }
                labels.push(label);
                idx += 1;
            }
        }
        labels
    }

    /// Returns the MACs for each output wire.
    pub fn collect_output_macs(&self) -> Vec<Mac> {
        let outputs = self
            .circ
            .outputs()
            .iter()
            .flat_map(|group| {
                group.iter().map(|node| self.auth_bits[node.id()].mac)
            })
            .collect();
        outputs
    }
}
