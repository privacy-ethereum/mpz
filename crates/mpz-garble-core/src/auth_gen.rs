use crate::{
    circuit::{sigma, AuthHalfGate}, 
    fpre::{AuthBitShare, AuthTripleShare, FpreGen}, 
    Party
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

/// Errors that can occur during authenticated garbled circuit generation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum AuthGeneratorError {
    #[error(transparent)]
    TypeError(#[from] TypeError),
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("generator not finished")]
    NotFinished,
    #[error("MAC verification failed at gate {0}")]
    MacCheckFailed(usize), 
    #[error("expected {expected} input labels, got {actual}")]
    InvalidLabelCount { expected: usize, actual: usize },
    #[error("expected {expected} auth bits, got {actual}")]
    InvalidAuthBitCount { expected: usize, actual: usize },
    #[error("expected {expected} AND gates, got {actual}")]
    InvalidPxPyCount { expected: usize, actual: usize },
    #[error("expected {expected} input MACs, got {actual}")]
    InvalidInputMacCount { expected: usize, actual: usize },
}

/// Uses a random triple and derandomization bits to compute the shares of AND of auth bits
#[inline]
pub(crate) fn sigma_share(triple: &mut AuthTripleShare, px: bool, py: bool, delta_a: Block) -> AuthBitShare {
    let mut sigma_share = triple.z.clone();

    if px {
        sigma_share = sigma_share + triple.y;
    }
    
    if py {
        sigma_share = sigma_share + triple.x;
    }

    if px && py {
        sigma_share.key = sigma_share.key + Key::from(delta_a); 
    }

    sigma_share
}

/// Garbles a single AND gate, computing the half-gate tables and output label
#[inline]
pub(crate) fn and_gate(
    lx: Block,
    ly: Block,
    sx: AuthBitShare,
    sy: AuthBitShare,
    sz: AuthBitShare,
    ss: AuthBitShare,
    delta_a: Block,
    cipher: &FixedKeyAes,  
    gid: usize,
) -> (AuthHalfGate, Block) {
    // Compute 1-bit labels
    let lx1 = lx ^ delta_a;
    let ly1 = ly ^ delta_a;
    
    // Pre-compute all hashes
    let j = Block::new((gid as u128).to_be_bytes());
    let k = Block::new(((gid + 1) as u128).to_be_bytes());
    // let mut h = [lx, ly, lx1, ly1];
    // cipher.tccr_many(&[j, k, j, k], &mut h);
    // let [hx, hy, hx1, hy1] = h;

    let hx = sigma(j, lx, cipher);
    let hy = sigma(k, ly, cipher);
    let hx1 = sigma(j, lx1, cipher);
    let hy1 = sigma(k, ly1, cipher);
    
    let g_0 = hx ^ hx1 ^ sy.key.as_block() ^ delta_a.mul_bool(sy.bit());
              
    let g_1 = hy ^ hy1 ^ sx.key.as_block() ^ delta_a.mul_bool(sx.bit()) ^ lx;
    
    // Compute output label
    let lz = hx ^ hy ^ sz.key.as_block() ^ delta_a.mul_bool(sz.bit()) ^ 
            ss.key.as_block() ^ delta_a.mul_bool(ss.bit());
    
    // Create half-gate with mask based on lz's LSB
    let gates = [g_0, g_1];
    let mask = lz.lsb();
    
    (AuthHalfGate::new(gates, mask), lz)
}

pub(crate) fn check_and(
    ss: &AuthBitShare,
    sz: &AuthBitShare,
    sx: &AuthBitShare,
    sy: &AuthBitShare,
    za: bool,
    zb: bool,
    zc: bool,
    delta_a: Block,
) -> Block {
    // Start with combined share of sigma and z
    let mut share = ss.mac.as_block() ^ ss.key.as_block() ^ 
    delta_a.mul_bool(ss.bit()) ^ 
    sz.mac.as_block() ^ sz.key.as_block() ^ 
    delta_a.mul_bool(sz.bit());

    // Apply adjustments based on masked values
    if za {
        share = share ^ sy.mac.as_block() ^ sy.key.as_block() ^ 
        delta_a.mul_bool(sy.bit());
    }

    if zb {
        share = share ^ sx.mac.as_block() ^ sx.key.as_block() ^ 
        delta_a.mul_bool(sx.bit());
    }

    if (za && zb) != zc {
        share = share ^ delta_a;
    }

    share
}

/// Authenticated garbled circuit generator.
///
/// Responsible for generating and managing authenticated garbled circuits
/// using preprocessed data from FpreGen.
#[derive(Debug)]
pub struct AuthGenerator<'a> {
    /// Generator's share of Fpre data.
    pub fpre: FpreGen,
    /// 0-bit labels for each wire in the circuit.
    pub labels: Vec<Block>,
    /// Authenticated bit shares for each wire.
    pub auth_bits: Vec<AuthBitShare>,
    /// A parallel buffer of AuthBitShares for each wire
    pub sigma_bits: Vec<AuthBitShare>,
    /// Masked values for each wire.
    pub masked_values: Vec<bool>,
    /// Reference to the circuit to be garbled.
    pub circ: &'a Circuit,
    /// The input owners for the circuit (Generator or Evaluator)
    pub input_owners: Vec<Party>,
    /// Gate ID
    pub gid: usize,
}

impl<'a> AuthGenerator<'a> {
    /// Creates a new `AuthGenerator` from FpreGen and circuit.
    ///
    /// # Arguments
    /// * `circ` - Reference to the circuit to be garbled
    /// * `fpre` - Preprocessed data for authenticated garbling
    /// * `input_owners` - Vector specifying the owner (Generator or Evaluator) of each input wire
    pub fn new(circ: &'a Circuit, fpre: FpreGen, input_owners: Vec<Party>) -> Self {
        Self {
            fpre,
            labels: Vec::new(),
            auth_bits: Vec::new(),
            sigma_bits: Vec::new(),
            masked_values: Vec::new(),
            circ,
            input_owners,
            gid: 1,
        }
    }

    /// Initializes the generator with the given zero-bit labels.
    pub fn initialize(
        &mut self,
        zero_labels: Vec<Block>,
    ) -> Result<(), AuthGeneratorError> {
        self.validate_initialization_inputs(&zero_labels)?;
        self.resize_internal_buffers();
        self.assign_labels_and_auth_bits(zero_labels);
        Ok(())
    }

    /// Validates that we have sufficient inputs for initialization
    fn validate_initialization_inputs(&self, zero_labels: &[Block]) -> Result<(), AuthGeneratorError> {
        // Check if zero_labels has enough labels
        if self.circ.input_len() > zero_labels.len() {
            return Err(AuthGeneratorError::InvalidLabelCount {
                expected: self.circ.input_len(),
                actual: zero_labels.len(),
            });
        }

        // Check if fpre has enough auth bits
        if self.circ.input_len() + self.circ.and_count() > self.fpre.wire_shares.len() {
            return Err(AuthGeneratorError::InvalidAuthBitCount {
                expected: self.circ.input_len() + self.circ.and_count(),
                actual: self.fpre.wire_shares.len(),
            });
        }

        Ok(())
    }

    /// Resizes internal buffers to accommodate circuit size
    fn resize_internal_buffers(&mut self) {
        if self.circ.feed_count() > self.labels.len() {
            self.labels.resize(self.circ.feed_count(), Default::default());
        }

        if self.circ.feed_count() > self.auth_bits.len() {
            self.auth_bits.resize(self.circ.feed_count(), Default::default());
        }
    }

    /// Assigns labels and auth bits to input wires and AND gate outputs
    fn assign_labels_and_auth_bits(&mut self, zero_labels: Vec<Block>) {
        let mut count = 0;
        let mut zero_labels_iter = zero_labels.into_iter();

        // Fill labels, auth bits for input wires
        for input in self.circ.inputs() {
            for (node, label) in input.iter().zip(zero_labels_iter.by_ref()) {
                self.labels[node.id()] = label;
                self.auth_bits[node.id()] = self.fpre.wire_shares[count];
                count += 1;
            }
        }

        // Fill auth bits for output wires of AND gates as well
        for gate in self.circ.gates() {
            if let Gate::And { x: _, y: _, z } = gate {
                self.auth_bits[z.id()] = self.fpre.wire_shares[count];
                count += 1;
            }
        }
    }

    //
    // Gate Evaluation Methods
    //

    /// Handles free gates (XOR/NOT), skipping AND gates.
    pub fn evaluate_free_gates(&mut self) {
        let delta_a = self.fpre.delta_a.into_inner();
        
        for gate in self.circ.gates() {
            match gate {
                Gate::Xor { x, y, z } => {
                    self.labels[z.id()] = self.labels[x.id()] ^ self.labels[y.id()];
                    self.auth_bits[z.id()] = self.auth_bits[x.id()] + self.auth_bits[y.id()];
                }
                Gate::Inv { x, z } => {
                    self.labels[z.id()] = self.labels[x.id()] ^ delta_a;
                    self.auth_bits[z.id()] = self.auth_bits[x.id()].clone();
                }
                Gate::And { .. } => {
                    // AND gates are handled separately
                }
            }
        }
    }

    /// Produces `(px, py)` derandomization bits for each AND gate,
    /// based on the auth bit and triple from `fpre.triple_shares`.
    pub fn prepare_px_py(&mut self) -> (Vec<bool>, Vec<bool>) {
        let mut px = Vec::with_capacity(self.circ.and_count());
        let mut py = Vec::with_capacity(self.circ.and_count());
        let mut and_count = 0;

        for gate in self.circ.gates() {
            if let Gate::And { x, y, .. } = gate {
                let sx = &self.auth_bits[x.id()];
                let sy = &self.auth_bits[y.id()];
                let triple = &self.fpre.triple_shares[and_count];
                
                px.push(sx.bit() ^ triple.x.bit());
                py.push(sy.bit() ^ triple.y.bit());
                and_count += 1;
            }
        }
        
        (px, py)
    }

    /// Generates and encrypts generator's AND gate table shares.
    pub fn garble_and_gates(
        &mut self,
        cipher: &FixedKeyAes,
        px_vec: Vec<bool>,
        py_vec: Vec<bool>,
    ) -> Result<Vec<AuthHalfGate>, AuthGeneratorError> {
        // Validate inputs
        if px_vec.len().min(py_vec.len()) < self.circ.and_count() {
            return Err(AuthGeneratorError::InvalidPxPyCount {
                expected: self.circ.and_count(),
                actual: px_vec.len().min(py_vec.len()),
            });
        }
        
        let delta_a = self.fpre.delta_a.into_inner();
        let mut and_gates = Vec::with_capacity(self.circ.and_count());
        let mut and_count = 0;
        
        // Reserve space for sigma bits
        self.sigma_bits.clear();
        self.sigma_bits.reserve(self.circ.and_count());

        for gate in self.circ.gates() {
            if let Gate::And { x, y, z } = gate {
                let lx = self.labels[x.id()];
                let ly = self.labels[y.id()];
                let sx = self.auth_bits[x.id()];
                let sy = self.auth_bits[y.id()];
                let triple = &mut self.fpre.triple_shares[and_count];

                // Calculate adjusted px and py values
                let px = sx.bit() ^ triple.x.bit() ^ px_vec[and_count];
                let py = sy.bit() ^ triple.y.bit() ^ py_vec[and_count];

                // Compute sigma share for this gate
                let ss = sigma_share(triple, px, py, delta_a);

                // Get preprocessed share for wire z
                let sz = self.auth_bits[z.id()];

                // Garble the gate and compute output label
                let (half_gate, lz) = and_gate(lx, ly, sx, sy, sz, ss, delta_a, cipher, self.gid);
                self.labels[z.id()] = lz;
                
                self.sigma_bits.push(ss);
                and_gates.push(half_gate);
                and_count += 1;
                self.gid += 2;
            }
        }

        Ok(and_gates)
    }

    /// Generator outputs MACs for each input wire owned by Evaluator
    pub fn collect_input_macs(&self) -> Vec<(bool, Mac)> {
        let mut macs = Vec::new();
        
        for input_group in self.circ.inputs() {
            for node in input_group.iter() {
                // If this input is owned by Evaluator, collect the MAC
                if self.input_owners[node.id()] == Party::Evaluator {
                    let auth_bit = &self.auth_bits[node.id()];
                    macs.push((auth_bit.bit(), auth_bit.mac));
                }
            }
        }
        
        macs
    }

    /// Verifies Evaluator's MACs for Generator's input wires, returning Generator's `masked_inputs`.

    pub fn collect_masked_inputs(
        &mut self, 
        gen_inputs: Vec<bool>, 
        gen_input_macs: Vec<(bool, Mac)>
    ) -> Result<Vec<bool>, AuthGeneratorError> {
        let delta_a = self.fpre.delta_a.into_inner();
        
        // Count Generator inputs
        let num_gen_inputs = self.input_owners
            .iter()
            .filter(|&p| *p == Party::Generator)
            .count();

        // Validate input counts
        if gen_input_macs.len() != num_gen_inputs || gen_inputs.len() != num_gen_inputs {
            return Err(AuthGeneratorError::InvalidInputMacCount {
                expected: num_gen_inputs,
                actual: gen_input_macs.len().min(gen_inputs.len()),
            });
        }

        // Verify MACs and generate masked inputs
        let mut masked_inputs = Vec::with_capacity(num_gen_inputs);
        let mut idx = 0;
        
        for input in self.circ.inputs() {
            for node in input.iter() {
                if self.input_owners[node.id()] == Party::Generator {                
                    let (bit, mac) = gen_input_macs[idx];
                    let mut mac_block = mac.as_block().clone();
                    let key_block = self.auth_bits[node.id()].key.as_block().clone();
                    
                    // Adjust MAC if bit is 1
                    if bit {
                        mac_block = mac_block ^ delta_a;
                    }

                    // Verify MAC
                    if key_block != mac_block {
                        return Err(AuthGeneratorError::MacCheckFailed(idx));
                    }

                    // Compute masked input
                    let masked_input = self.auth_bits[node.id()].bit() ^ gen_inputs[idx] ^ bit;
                    masked_inputs.push(masked_input);
                    idx += 1;
                }
            }
        }

        Ok(masked_inputs) 
    }

    /// Collect the input labels corresponding to masked_inputs for the evaluator and generator.
    pub fn collect_input_labels(&self, masked_inputs: &[bool]) -> Vec<Block> {
        let delta_a = self.fpre.delta_a.into_inner();
        let mut labels = Vec::with_capacity(masked_inputs.len());
        let mut idx = 0;
        
        for input in self.circ.inputs() {
            for node in input.iter() {
                let mut label = self.labels[node.id()];
                
                // Adjust label if masked input bit is 1
                if masked_inputs[idx] {
                    label = label ^ delta_a;
                }
                
                labels.push(label);
                idx += 1;
            }
        }
        
        labels
    }

    /// Sets the masked values for the generator.
    pub fn set_masked_values(&mut self, masked_values: Vec<bool>) {
        self.masked_values = masked_values;
    }

    /// Authenticates the circuit using the sigma shares and auth bits.
    pub fn authenticate(&self, cipher: &FixedKeyAes) -> Block {
        let mut hash = Block::ZERO;
        let mut and_count = 0;
        let delta_a = self.fpre.delta_a.into_inner();
        
        for gate in self.circ.gates() {
            if let Gate::And { x, y, z } = gate {
                let ss = &self.sigma_bits[and_count];
                let sz = &self.auth_bits[z.id()];
                let sx = &self.auth_bits[x.id()];
                let sy = &self.auth_bits[y.id()];

                // Get masked values
                let za = self.masked_values[x.id()];
                let zb = self.masked_values[y.id()];
                let zc = self.masked_values[z.id()];

                let share = check_and(ss, sz, sx, sy, za, zb, zc, delta_a);
                
                // Update hash                            
                hash ^= sigma(Block::new((and_count as u128).to_be_bytes()), share, cipher);
                and_count += 1;
            }
        }
        
        hash
    }

    /// Returns the Generator's MACs for each output wire.
    pub fn collect_output_macs(&self) -> Vec<(bool, Mac)> {
        self.circ
            .outputs()
            .iter()
            .flat_map(|group| {
                group.iter().map(|node| {
                    let auth_bit = &self.auth_bits[node.id()];
                    (auth_bit.bit(), auth_bit.mac)
                })
            })
            .collect()
    }
}
