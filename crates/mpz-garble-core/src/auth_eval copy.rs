use mpz_memory_core::correlated::Mac;

use crate::{circuit::{sigma, AuthHalfGate}, fpre::AuthTripleShare};
use mpz_circuits::{
    types:: TypeError,
    Circuit, CircuitError, Gate,
};
use mpz_core::{
    aes::FixedKeyAes,
    Block,
};

use crate::{fpre::{FpreEval, AuthBitShare}, Party};

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

/// Authenticated garbled circuit evaluator.
///
/// Responsible for evaluating authenticated garbled circuits
/// using preprocessed data from FpreEval.
#[derive(Debug)]
pub struct AuthEvaluator<'a> {
    /// The evaluator's shares and delta from the function-independent Fpre phase.
    pub fpre: FpreEval,
    /// labels for evaluation
    pub labels: Vec<Block>,
    /// A parallel buffer of AuthBitShares for each wire
    pub auth_bits: Vec<AuthBitShare>,
    /// A parallel buffer of AuthBitShares for each wire
    pub sigma_bits: Vec<AuthBitShare>,
    /// A parallel buffer of AuthBitShares for each wire
    pub masked_values: Vec<bool>,
    /// The circuit to garble
    pub circ: &'a Circuit,
    /// The input owners for the circuit (Generator or Evaluator)
    pub input_owners: Vec<Party>,
    /// Gate ID
    pub gid: usize,
}

impl<'a> AuthEvaluator<'a> {
    /// Creates a new `AuthEvaluator` from FpreEval and circuit.
    pub fn new(circ: &'a Circuit, fpre: FpreEval, input_owners: Vec<Party>) -> Self {
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

    //
    // Initialization and Setup Methods
    //

    /// Initializes evaluator's auth bits using fpre.
    pub fn initialize(&mut self) -> Result<(), AuthEvaluatorError> {
        self.validate_initialization_inputs()?;
        self.resize_internal_buffers();
        self.assign_auth_bits();
        Ok(())
    }

    /// Validates that we have sufficient auth bits for initialization
    fn validate_initialization_inputs(&self) -> Result<(), AuthEvaluatorError> {
        // Check if fpre has enough auth bits
        if self.circ.input_len() + self.circ.and_count() > self.fpre.wire_shares.len() {
            return Err(AuthEvaluatorError::InvalidAuthBitCount {
                expected: self.circ.input_len() + self.circ.and_count(),
                actual: self.fpre.wire_shares.len(),
            });
        }
        Ok(())
    }

    /// Resizes internal buffers to accommodate circuit size
    fn resize_internal_buffers(&mut self) {
        if self.circ.feed_count() > self.auth_bits.len() {
            self.auth_bits.resize(self.circ.feed_count(), Default::default());
        }
    }

    /// Assigns auth bits to input wires and AND gate outputs
    fn assign_auth_bits(&mut self) {
        let mut count = 0;

        // Fill auth bits for input wires
        for input in self.circ.inputs() {
            for node in input.iter() {
                self.auth_bits[node.id()] = self.fpre.wire_shares[count];
                count += 1;
            }
        }

        // Fill auth bits for output wires of AND gates
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
        for gate in self.circ.gates() {
            match gate {
                Gate::Xor { x, y, z } => {
                    let sx = self.auth_bits[x.id()];
                    let sy = self.auth_bits[y.id()];
                    self.auth_bits[z.id()] = sx + sy;
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
        let mut px = Vec::with_capacity(self.circ.and_count());
        let mut py = Vec::with_capacity(self.circ.and_count());
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

    /// Evaluates all gates in the circuit, using the tables and gates for AND gates.
    pub fn evaluate(
        &mut self,
        px_vec: Vec<bool>,
        py_vec: Vec<bool>,
        gates: Vec<AuthHalfGate>,
        cipher: &FixedKeyAes
    ) -> Result<(), AuthEvaluatorError> {
        let mut and_count = 0;

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
                    let sx = self.auth_bits[x.id()];
                    let sy = self.auth_bits[y.id()];

                    // Get labels for input wires
                    let lx = self.labels[x.id()];
                    let ly = self.labels[y.id()];

                    // Get triple for this AND gate
                    let triple = &mut self.fpre.triple_shares[and_count];

                    // Compute px and py values
                    let mut px = sx.bit() ^ triple.x.bit();
                    let mut py = sy.bit() ^ triple.y.bit();

                    // Apply correction from px_vec and py_vec
                    px ^= px_vec[and_count];
                    py ^= py_vec[and_count];

                    // Compute sigma share for this AND gate
                    let ss = sigma_share(triple, px, py);
                    self.sigma_bits.push(ss);

                    // Get preprocessed (mac, key) for output wire
                    let sz = self.auth_bits[z.id()];

                    // Get masked input bits
                    let za = self.masked_values[x.id()];
                    let zb = self.masked_values[y.id()];

                    // Evaluate the AND gate
                    let (lz, zc) = and_gate(
                        lx, 
                        ly, 
                        sx, 
                        sy, 
                        sz, 
                        ss, 
                        &gates[and_count], 
                        za, 
                        zb, 
                        cipher, 
                        self.gid
                    );

                    // Set output masked value and label
                    self.masked_values[z.id()] = zc;
                    self.labels[z.id()] = lz;

                    and_count += 1;
                    self.gid += 2;
                }
            }
        }
        Ok(())
    }

    //
    // Input/Output Processing Methods
    //

    /// Evaluator outputs MACs for each input wire owned by Generator
    pub fn collect_input_macs(&self) -> Vec<(bool, Mac)> {
        let mut macs = Vec::new();
        for input_group in self.circ.inputs() {
            for node in input_group.iter() {
                // If this input is owned by Generator, collect the MAC
                if self.input_owners[node.id()] == Party::Generator {
                    macs.push((self.auth_bits[node.id()].bit(), self.auth_bits[node.id()].mac));
                }
            }
        }
        macs
    }

    /// Verifies Generator's MACs for Evaluator's input wires, returning Evaluator's `masked_inputs`.
    pub fn collect_masked_inputs(
        &mut self,
        eval_inputs: Vec<bool>,
        eval_input_macs: Vec<(bool, Mac)>
    ) -> Result<Vec<bool>, AuthEvaluatorError> {
        let delta_b = self.fpre.delta_b.into_inner();
        
        // Count instances of Party::Evaluator in self.input_owners
        let num_eval_inputs = self.input_owners
            .iter()
            .filter(|&p| *p == Party::Evaluator)
            .count();

        // Check if received MACs and inputs have the same length
        if eval_input_macs.len() != num_eval_inputs || eval_inputs.len() != num_eval_inputs {
            return Err(AuthEvaluatorError::InvalidInputMacCount {
                expected: num_eval_inputs,
                actual: eval_input_macs.len().min(eval_inputs.len()),
            });
        }

        // Verify MACs and generate masked inputs
        let mut masked_inputs = Vec::new();
        let mut idx = 0;
        for input in self.circ.inputs() {
            for node in input.iter() {
                if self.input_owners[node.id()] == Party::Evaluator {                
                    let mut mac = eval_input_macs[idx].1.as_block().clone(); 
                    let key = self.auth_bits[node.id()].key.as_block().clone();
                    
                    let bit = eval_input_macs[idx].0;

                    if bit {
                        mac = mac ^ delta_b;
                    }

                    if key != mac {
                        return Err(AuthEvaluatorError::MacCheckFailed(idx));
                    }

                    let masked_input = self.auth_bits[node.id()].bit() ^ eval_inputs[idx] ^ bit;
                    masked_inputs.push(masked_input);
                    idx += 1;
                }
            }
        }

        Ok(masked_inputs)
    }

    /// Set the input labels for the evaluator.
    pub fn set_input_labels(&mut self, input_labels: Vec<Block>) {
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

    /// Set the masked values for the evaluator.
    pub fn set_masked_inputs(&mut self, masked_inputs: Vec<bool>) {
        let mut idx = 0;
        if self.circ.feed_count() > self.masked_values.len() {
            self.masked_values.resize(self.circ.feed_count(), Default::default());
        }
        for node in self.circ.inputs().iter() {
            for node in node.iter() {
                self.masked_values[node.id()] = masked_inputs[idx];
                idx += 1;
            }
        }
    }

    /// Returns the masked values for the evaluator.
    pub fn masked_values(&self) -> Vec<bool> {
        self.masked_values.clone()
    }

    /// Returns the check shares for the evaluator.
    pub fn authenticate(&self, cipher: &FixedKeyAes) -> Block {
        let mut hash = Block::ZERO;
        let mut and_count = 0;
        let delta_b = self.fpre.delta_b.into_inner();
        
        for gate in self.circ.gates() {
            if let Gate::And { x, y, z } = gate {
                // Get sigma and auth bit shares
                let ss = self.sigma_bits[and_count];
                let sz = self.auth_bits[z.id()];
                let sx = self.auth_bits[x.id()];
                let sy = self.auth_bits[y.id()];

                // Get masked values
                let za = self.masked_values[x.id()];
                let zb = self.masked_values[y.id()];
                let zc = self.masked_values[z.id()];
                
                // Compute authentication share
                let share = check_and(
                    &ss,
                    &sz,
                    &sx,
                    &sy,
                    za,
                    zb,
                    zc,
                    delta_b
                );
                
                // Add to hash
                hash ^= sigma(Block::new((and_count as u128).to_be_bytes()), share, cipher);
                and_count += 1;
            }
        }
        
        hash
    }

    /// Verifies MAC of gen's share of output mask and reconstructs output bits.
    pub fn finalize_outputs(
        &mut self,
        gen_output_macs: Vec<(bool, Mac)>,
    ) -> Result<Vec<bool>, AuthEvaluatorError> {
        let delta_b = self.fpre.delta_b.into_inner();

        // Validate we have the correct number of output MACs
        if gen_output_macs.len() != self.circ.output_len() {
            return Err(AuthEvaluatorError::InvalidOutputMacCount {
                expected: self.circ.output_len(),
                actual: gen_output_macs.len(),
            });
        }

        let mut final_bits = Vec::with_capacity(gen_output_macs.len());
        let mut mac_idx = 0;

        // Process each output node
        for output_group in self.circ.outputs() {
            for node in output_group.iter() {
                // Get generator's MAC and bit
                let (gen_bit, gen_mac) = gen_output_macs[mac_idx];
                
                // Adjust MAC with delta if bit is 1
                let mut mac = gen_mac.as_block().clone();
                if gen_bit {
                    mac ^= delta_b;
                }
    
                // Verify MAC against our key
                let key = self.auth_bits[node.id()].key.as_block().clone();
                if key != mac {
                    return Err(AuthEvaluatorError::MacCheckFailed(mac_idx));
                }
    
                // Reconstruct the actual output bit
                let eval_masked_bit = self.masked_values[node.id()];
                let eval_auth_bit = self.auth_bits[node.id()].bit();
                let output_bit = eval_masked_bit ^ eval_auth_bit ^ gen_bit;
    
                final_bits.push(output_bit);
                mac_idx += 1;
            }
        }

        Ok(final_bits)
    }
}

/// Computes the sigma share from a triple, px, and py
pub(crate) fn sigma_share(triple: &mut AuthTripleShare, px: bool, py: bool) -> AuthBitShare {
    let mut sigma_share = triple.z.clone();

    if px {
        sigma_share = sigma_share + triple.y;
    }
    
    if py {
        sigma_share = sigma_share + triple.x;
    }

    if px && py {
        sigma_share.value = !sigma_share.value;
    }

    sigma_share
}

/// Evaluates a single AND gate, computing the output label
#[inline]
pub(crate) fn and_gate(
    lx: Block,
    ly: Block,
    sx: AuthBitShare,
    sy: AuthBitShare,
    sz: AuthBitShare,
    ss: AuthBitShare,
    gates: &AuthHalfGate,
    za: bool,
    zb: bool,
    cipher: &FixedKeyAes,
    gid: usize,
) -> (Block, bool) {
    // Compute garbled gate values
    let g_0 = gates.gates[0] ^ sy.mac.as_block();
    let g_1 = gates.gates[1] ^ sx.mac.as_block();

    // Compute output label
    let j = Block::new((gid as u128).to_be_bytes());
    let k = Block::new(((gid + 1) as u128).to_be_bytes());

    let hx = sigma(j, lx, cipher);
    let hy = sigma(k, ly, cipher);

    let sz_mac = sz.mac.as_block();
    let ss_mac = ss.mac.as_block();

    let mut lz = hx ^ hy ^ sz_mac ^ ss_mac ^ (g_0.mul_bool(za)) ^ ((g_1^lx).mul_bool(zb));

    // Compute masked value
    let zc = lz.lsb() ^ gates.mask;
    lz.set_lsb(zc);
    
    (lz, zc)
}

/// Computes the authentication share for an AND gate
pub(crate) fn check_and(
    ss: &AuthBitShare,
    sz: &AuthBitShare,
    sx: &AuthBitShare,
    sy: &AuthBitShare,
    za: bool,
    zb: bool,
    zc: bool,
    delta_b: Block,
) -> Block {
    // Compute share components
    let ss_mac_key = ss.mac.as_block() ^ ss.key.as_block() ^ delta_b.mul_bool(ss.bit());
    let sz_mac_key = sz.mac.as_block() ^ sz.key.as_block() ^ delta_b.mul_bool(sz.bit());
    
    // Start with sigma and z shares
    let mut share = ss_mac_key ^ sz_mac_key;
    
    // Add x and y shares if masked values are true
    if za {
        let sy_mac_key = sy.mac.as_block() ^ sy.key.as_block() ^ delta_b.mul_bool(sy.bit());
        share = share ^ sy_mac_key;
    }
    
    if zb {
        let sx_mac_key = sx.mac.as_block() ^ sx.key.as_block() ^ delta_b.mul_bool(sx.bit());
        share = share ^ sx_mac_key;
    }
    
    // Check if AND gate is correct
    if (za && zb) != zc {
        share = share ^ delta_b;
    }
    
    share
}

