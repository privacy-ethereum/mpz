use std::fmt;
use mpz_memory_core::correlated::{Mac, Delta, Key};

use crate::{circuit::{sigma, AuthHalfGate}, fpre::AuthTripleShare};
use mpz_circuits::{
    types::{TypeError, BinaryRepr},
    Circuit, CircuitError, Gate,
};
use mpz_core::{
    aes::{FixedKeyAes, FIXED_KEY_AES},
    Block,
};

use crate::{fpre::{FpreEval, AuthBitShare}, circuit::AuthHalfGateBatch, Party, DEFAULT_BATCH_SIZE};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

const SELECT_MASK: [Block; 2] = [Block::ZERO, Block::ONES];

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

// insecure hash function
fn h2d(a: Block, b: Block) -> Block {
    let mut d = [a, a ^ b];
    d[0] = d[0] ^ d[1]; 
    return d[0] ^ b;
}

// insecure hash function
fn h2(a: Block, b: Block) -> Block {
    let mut d = [a, b];
    d[0] = d[0] ^ d[1];
    d[0] = d[0] ^ a;
    return d[0] ^ b;
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
    encrypted_gate: AuthHalfGate,
    za: bool,
    zb: bool,
    cipher: &FixedKeyAes,
    gid: usize,
) -> (Block, bool) {
    // Compute garbled gate values
    let g_0 = encrypted_gate.gates[0] ^ sy.mac.as_block();
    let g_1 = encrypted_gate.gates[1] ^ sx.mac.as_block();

    // Compute output label
    let j = Block::new((gid as u128).to_be_bytes());
    let k = Block::new(((gid + 1) as u128).to_be_bytes());

    let mut h = [lx, ly];
    cipher.tccr_many(&[j, k], &mut h);
    let [hx, hy] = h;

    // let hx = sigma(j, lx, cipher);
    // let hy = sigma(k, ly, cipher);

    let sz_mac = sz.mac.as_block();
    let ss_mac = ss.mac.as_block();

    let lz = hx ^ hy ^ sz_mac ^ ss_mac ^ (g_0.mul_bool(za)) ^ ((g_1^lx).mul_bool(zb));

    // Compute masked value
    let zc = lz.lsb() ^ encrypted_gate.mask;
    // lz.set_lsb(zc);
    
    (lz, zc)
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

/// Computes the authentication share for an AND gate
pub(crate) fn check_and(
    ss: &AuthBitShare,
    sz: &AuthBitShare,
    sx: &AuthBitShare,
    sy: &AuthBitShare,
    za: bool,
    zb: bool,
    zc: bool,
    delta: Block,
) -> Block {
    // Start with combined share of sigma and z
    let mut share = (ss.mac.as_block() ^ ss.key.as_block() ^ delta.mul_bool(ss.bit())) ^
                   (sz.mac.as_block() ^ sz.key.as_block() ^ delta.mul_bool(sz.bit()));

    // Apply adjustments based on masked values
    if za {
        share = share ^ sy.mac.as_block() ^ sy.key.as_block() ^ 
        delta.mul_bool(sy.bit());
    }

    if zb {
        share = share ^ sx.mac.as_block() ^ sx.key.as_block() ^ 
        delta.mul_bool(sx.bit());
    }

    if (za && zb) != zc {
        share = share ^ delta;
    }

    share
}

/// Output of the evaluator.
#[derive(Debug)]
pub struct AuthEvalOutput {
    /// Output labels of the circuit.
    pub output_labels: Vec<Mac>,
    /// Output auth bits of the circuit.
    pub output_auth_bits: Vec<AuthBitShare>,
    /// Authentication hash of the circuit.
    pub auth_hash: Block,
    /// Output values of the circuit.
    pub masked_output_values: Vec<bool>,
    /// All masked values of the circuit.
    pub masked_values: Vec<bool>,
}

/// Garbled circuit evaluator.
#[derive(Debug, Default)]
pub struct AuthEval {
    labels: Vec<Block>, 
    auth_bits: Vec<AuthBitShare>,
    sigma_bits: Vec<AuthBitShare>,
    masked_values: Vec<bool>,
    // Preprocessed triples, consumed to generate sigma_bits
    triples: Vec<AuthTripleShare>,
    leaky_triples: Vec<AuthTripleShare>,
    permutation: Vec<usize>,
    seed: u64, // via secure coin toss
    bucket_size: usize,
}

// TODO: set input labels at the end
impl AuthEval {

    /// Create a new AuthEval with seed from coin-tossing
    pub fn new(seed: u64, bucket_size: usize) -> Self {
        Self {
            labels: vec![],
            auth_bits: vec![],
            sigma_bits: vec![],
            masked_values: vec![],
            triples: vec![],
            leaky_triples: vec![],
            permutation: vec![],
            seed,
            bucket_size,
        }
    }

    /// 1) Sets input auth bits and labels.
    /// 2) Uses auth bits from COT to set wire auth bits and output faulty triples.
    pub fn evaluate_pre_1<'a>(
        &'a mut self, 
        circ: &'a Circuit,
        delta: Delta,
        input_labels: Vec<Mac>,
        input_auth_bits: Vec<AuthBitShare>,
        masked_inputs: Vec<bool>,
        shares: Vec<AuthBitShare>,
    ) -> Result<(Vec<Block>, Vec<Block>), AuthEvaluatorError> {

        if input_labels.len() != circ.input_len() || input_auth_bits.len() != circ.input_len() || masked_inputs.len() != circ.input_len() {
            return Err(CircuitError::InvalidInputCount(
                circ.input_len(),
                input_labels.len(),
            ))?;
        }

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.labels.len() {
            self.labels.resize(circ.feed_count(), Default::default());
            self.auth_bits.resize(circ.feed_count(), Default::default());
            self.masked_values.resize(circ.feed_count(), false);
        }

        // Set input labels and auth bits
        let mut input_labels_iter = input_labels.into_iter();
        let mut input_auth_bits_iter = input_auth_bits.into_iter();
        let mut masked_inputs_iter = masked_inputs.into_iter();
        for input in circ.inputs() {
            for (node, label) in input.iter().zip(input_labels_iter.by_ref()) {
                self.labels[node.id()] = label.into();
            }
            for (node, auth_bit) in input.iter().zip(input_auth_bits_iter.by_ref()) {
                self.auth_bits[node.id()] = auth_bit;
            }
            for (node, masked_input) in input.iter().zip(masked_inputs_iter.by_ref()) {
                self.masked_values[node.id()] = masked_input;
            }
        }

        // Set AND output auth bits
        let mut count = 0;
        for gate in circ.gates() {
            if let Gate::And { x: _, y: _, z } = gate {
                self.auth_bits[z.id()] = shares[count];
                count += 1;
            }
        }

        // Set faulty triples
        let length = (shares.len() - count) / 3;
        for i in 0..length {
            self.leaky_triples.push(AuthTripleShare {
                x: shares[3 * i],
                y: shares[3 * i + 1],
                z: shares[3 * i + 2]
            });
        }

        let length = self.leaky_triples.len();
        let mut c = vec![Block::ZERO; length];
        let mut g = vec![Block::ZERO; length];

        for i in 0..length {
            c[i] = self.leaky_triples[i].y.mac.as_block().clone()
                ^ self.leaky_triples[i].y.key.as_block().clone()
                ^ (SELECT_MASK[self.leaky_triples[i].y.bit() as usize] & delta.as_block());

            g[i] = c[i] ^ h2d(self.leaky_triples[i].x.key.into(), delta.into_inner());
        }
        Ok((c, g))
    }

    /// Round 2
    pub fn evaluate_pre_2<'a>(
        &'a mut self, 
        delta: Delta,
        c: Vec<Block>, 
        g: &mut Vec<Block>, 
        gr: Vec<Block> // received
    ) -> Result<Vec<bool>, AuthEvaluatorError> {
        let length = self.leaky_triples.len();
        let mut d = vec![false; length];

        for i in 0..length {
            let mut s = h2(self.leaky_triples[i].x.mac.as_block().clone(), self.leaky_triples[i].x.key.as_block().clone());
            s = s ^ self.leaky_triples[i].z.mac.as_block().clone() ^ self.leaky_triples[i].z.key.as_block().clone();
            s = s ^ SELECT_MASK[self.leaky_triples[i].x.bit() as usize] & (gr[i] ^ c[i]);
            g[i] = s ^ SELECT_MASK[self.leaky_triples[i].z.bit() as usize] & delta.as_block();
            d[i] = g[i].lsb();
        }

        Ok(d)
    }

    /// Round 3
    pub fn evaluate_pre_3<'a>(
        &'a mut self, 
        delta: Delta,
        g: &mut Vec<Block>, 
        mut d: Vec<bool>, 
        dr: Vec<bool> // received
    ) -> Result<Vec<bool>, AuthEvaluatorError> {
        let length = self.leaky_triples.len();
        for i in 0..length {
            d[i] = d[i] ^ dr[i];
            if d[i] {
                self.leaky_triples[i].z.key = self.leaky_triples[i].z.key + Key::from(delta.into_inner());
                g[i] = g[i] ^ delta.as_block();
            }
        }

        let total = self.leaky_triples.len();
        let bucket_size = self.bucket_size;
        assert_eq!(total % bucket_size, 0,
            "total length must be multiple of bucket_size");
        let n = total / bucket_size;
    
        // Fisher–Yates shuffle in place
        let mut rng = ChaCha12Rng::seed_from_u64(self.seed);
        let mut location: Vec<usize> = (0..total).collect();
        for i in (0..total).rev() {
            let idx = rng.gen_range(0..=i);
            location.swap(i, idx);
        }

        self.permutation = location;
    
        let mut data = vec![false; total];
    
        for i in 0..n {
            let base_idx = self.permutation[i*bucket_size + 0];    
            let y_base = self.leaky_triples[base_idx].y.bit();
    
            for j in 1..bucket_size {
                let idx_j = self.permutation[i*bucket_size + j];
                let y_j = self.leaky_triples[idx_j].y.bit();
                data[i*bucket_size + j] = y_base ^ y_j;
            }
        }
        Ok(data)
    }

    /// Round 4
    pub fn evaluate_pre_4<'a>(
        &'a mut self,
        data: Vec<bool>,
        data_recv: Vec<bool>, // received
    ) -> Result<(), AuthEvaluatorError> {

        let total = self.leaky_triples.len();
        let bucket_size = self.bucket_size;
        assert_eq!(total % bucket_size, 0,
            "total length must be multiple of bucket_size");
        let n = total / bucket_size;

        let mut final_data = vec![false; total];
        for i in 0..total {
            final_data[i] = data[i] ^ data_recv[i];
        }

        for i in 0..n {
            let base_idx = self.permutation[i*bucket_size + 0];
    
            // Start with a "copy" of the first triple in the bucket
            let mut combined_share = self.leaky_triples[base_idx].clone();
    
            // For j in [1..bucket_size], merge x and z wires, keep y same as base
            for j in 1..bucket_size {
                let idx_j = self.permutation[i*bucket_size + j];
    
                combined_share.x = combined_share.x + self.leaky_triples[idx_j].x;
    
                combined_share.z = combined_share.z + self.leaky_triples[idx_j].z;
    
                // If d == 1, correct z-wire by xoring with x-wire
                if final_data[i*bucket_size + j] {
                    combined_share.z = combined_share.z + self.leaky_triples[idx_j].x;
                }
            }
            self.triples.push(combined_share);
        }
        Ok(())
    }

    /// Returns the output triples for debugging
    pub fn output_triples(&self) -> Vec<AuthTripleShare> {
        self.triples.clone()
    }

    /// Generates the free gates for the circuit.
    pub fn evaluate_free<'a>(
        &'a mut self, 
        circ: &'a Circuit,
    ) -> Result<(), AuthEvaluatorError> {
        for gate in circ.gates() {
            match gate {
                Gate::Xor { x, y, z } => {
                    // self.labels[z.id()] = self.labels[x.id()] ^ self.labels[y.id()];
                    self.auth_bits[z.id()] = self.auth_bits[x.id()] + self.auth_bits[y.id()];
                }
                Gate::Inv { x, z } => {
                    // self.labels[z.id()] = self.labels[x.id()] ^ delta.as_block();
                    self.auth_bits[z.id()] = self.auth_bits[x.id()].clone();
                }
                Gate::And { .. } => {
                    // AND gates are handled separately
                }
            }
        }
        Ok(())
    }

    /// Generates the derandomized bits for the circuit.
    pub fn evaluate_de<'a>(
        &'a mut self,
        circ: &'a Circuit,
    ) -> Result<(Vec<bool>, Vec<bool>), AuthEvaluatorError> {
        let mut px = Vec::with_capacity(circ.and_count());
        let mut py = Vec::with_capacity(circ.and_count());
        let mut and_count = 0;

        for gate in circ.gates() {
            if let Gate::And { x, y, .. } = gate {
                let sx = &self.auth_bits[x.id()];
                let sy = &self.auth_bits[y.id()];
                let triple = &self.triples[and_count];
                
                px.push(sx.bit() ^ triple.x.bit());
                py.push(sy.bit() ^ triple.y.bit());
                and_count += 1;
            }
        }
        
        Ok((px, py))
    }

    /// Generates an iterator over the encrypted gates of a circuit.
    pub fn evaluate<'a>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        px: Vec<bool>, // received
        py: Vec<bool>, // received
    ) -> Result<AuthEncryptedGateConsumer<'_, std::slice::Iter<'_, Gate>>, AuthEvaluatorError> {
        // Validate inputs
        if px.len().min(py.len()) < circ.and_count() {
            return Err(AuthEvaluatorError::InvalidPxPyCount {
                expected: circ.and_count(),
                actual: px.len().min(py.len()),
            });
        }

        let mut and_count = 0;
        
        // Reserve space for sigma bits
        self.sigma_bits.reserve(circ.and_count());

        for gate in circ.gates() {
            if let Gate::And { x, y, z: _ } = gate {
                let sx = self.auth_bits[x.id()];
                let sy = self.auth_bits[y.id()];
                let triple = &mut self.triples[and_count];

                // Calculate adjusted px and py values
                let px = sx.bit() ^ triple.x.bit() ^ px[and_count];
                let py = sy.bit() ^ triple.y.bit() ^ py[and_count];

                // Compute sigma share for this gate
                let ss = sigma_share(triple, px, py);
                
                self.sigma_bits.push(ss);
                and_count += 1;
            }
        }

        // self.masked_values.resize(circ.feed_count(), false);

        Ok(AuthEncryptedGateConsumer::new(
            delta,
            circ.gates().iter(),
            circ.gates().iter(),
            circ.outputs(),
            &mut self.labels,
            &mut self.auth_bits,
            &mut self.sigma_bits,
            &mut self.masked_values,
            circ.and_count(),
        ))
    }

    /// Returns a consumer over batched encrypted gates of a circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate.
    /// * `inputs` - The input labels to the circuit.
    pub fn evaluate_batched<'a>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        px: Vec<bool>,
        py: Vec<bool>,
    ) -> Result<AuthEncryptedGateBatchConsumer<'_, std::slice::Iter<'_, Gate>>, AuthEvaluatorError> {
        self.evaluate(circ, delta, px, py).map(AuthEncryptedGateBatchConsumer)
    }
    
}

/// Consumer over the encrypted gates of a circuit.
pub struct AuthEncryptedGateConsumer<'a, I: Iterator> {
   /// Cipher to use to encrypt the gates.
   cipher: &'static FixedKeyAes,
   /// Global offset.
   delta: Delta,
   /// Buffer for the 0-bit labels.
   labels: &'a mut [Block],
   /// Buffer for the auth bits.
   auth_bits: &'a mut [AuthBitShare],
   /// Buffer for the sigma bits.
   sigma_bits: &'a mut [AuthBitShare],
   /// Buffer for the masked values.
   masked_values: &'a mut [bool],
   /// Iterator over the gates.
   gates: I,
   /// Iterator over the gates.
   gates2: I,
   /// Circuit outputs.
   outputs: &'a [BinaryRepr],
   /// Current gate id.
   gid: usize,
   /// Number of AND gates generated.
   counter: usize,
   /// Number of AND gates in the circuit.
   and_count: usize,
   /// Whether the entire circuit has been garbled.
   complete: bool,
}

impl<'a, I: Iterator> fmt::Debug for AuthEncryptedGateConsumer<'a, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthEncryptedGateConsumer {{ .. }}")
    }
}

impl<'a, I> AuthEncryptedGateConsumer<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    fn new(
        delta: Delta,
        gates: I,
        gates2: I,
        outputs: &'a [BinaryRepr],
        labels: &'a mut [Block],
        auth_bits: &'a mut [AuthBitShare],
        sigma_bits: &'a mut [AuthBitShare],
        masked_values: &'a mut [bool],
        and_count: usize,
    ) -> Self {
        Self {
            cipher: &(*FIXED_KEY_AES),
            delta,
            gates,
            gates2,
            outputs,
            labels,
            auth_bits,
            sigma_bits,
            masked_values,
            gid: 1,
            counter: 0,
            and_count,
            complete: false,
        }
    }

    /// Returns `true` if the evaluator wants more encrypted gates.
    #[inline]
    pub fn wants_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Evaluates the next encrypted gate in the circuit.
    #[inline]
    pub fn next(&mut self, encrypted_gate: AuthHalfGate) {
        while let Some(gate) = self.gates.next() {
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

                    // Compute sigma share for this AND gate
                    let ss = self.sigma_bits[self.counter];

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
                        encrypted_gate, 
                        za, 
                        zb, 
                        self.cipher, 
                        self.gid
                    );

                    // Set output masked value and label
                    self.masked_values[z.id()] = zc;
                    self.labels[z.id()] = lz;

                    self.counter += 1;
                    self.gid += 2;
                }
            }
        }

        self.complete = true;
    }

    /// Returns the encoded outputs of the circuit.
    pub fn finish(mut self) -> Result<AuthEvalOutput, AuthEvaluatorError> {
        if self.wants_gates() {
            return Err(AuthEvaluatorError::NotFinished);
        }

        // If there were 0 AND gates in the circuit, we need to evaluate the "free"
        // gates now.
        if !self.complete {
            self.next(Default::default());
        }

        let mut output_labels = Vec::new();
        let mut output_auth_bits = Vec::new();
        let mut masked_output_values = Vec::new();

        for output in self.outputs.iter() {
            for node in output.iter() {
                output_labels.push(Mac::from(self.labels[node.id()]));
                output_auth_bits.push(self.auth_bits[node.id()]);
                masked_output_values.push(self.masked_values[node.id()]);
            }
        }

        let mut auth_hash = Block::ZERO;
        let mut and_count = 0;
        let delta = self.delta.as_block();
        
        for gate in self.gates2 {
            if let Gate::And { x, y, z } = gate {
                let ss = &self.sigma_bits[and_count];
                let sz = &self.auth_bits[z.id()];
                let sx = &self.auth_bits[x.id()];
                let sy = &self.auth_bits[y.id()];

                // Get masked values
                let za = self.masked_values[x.id()];
                let zb = self.masked_values[y.id()];
                let zc = self.masked_values[z.id()];

                let share = check_and(ss, sz, sx, sy, za, zb, zc, *delta);
                
                // Update hash                            
                auth_hash ^= self.cipher.tccr(Block::new((and_count as u128).to_be_bytes()), share);
                and_count += 1;
            }
        }

        let masked_values = self.masked_values.to_vec();

        Ok(AuthEvalOutput { output_labels, output_auth_bits, masked_output_values, masked_values, auth_hash })
    }
}

/// Consumer returned by [`Evaluator::evaluate_batched`].
#[derive(Debug)]
pub struct AuthEncryptedGateBatchConsumer<'a, I: Iterator, const N: usize = DEFAULT_BATCH_SIZE>(
    AuthEncryptedGateConsumer<'a, I>,
);

impl<'a, I, const N: usize> AuthEncryptedGateBatchConsumer<'a, I, N>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if the evaluator wants more encrypted gates.
    pub fn wants_gates(&self) -> bool {
        self.0.wants_gates()
    }

    /// Evaluates the next batch of gates in the circuit.
    #[inline]
    pub fn next(&mut self, batch: AuthHalfGateBatch<N>) {
        for encrypted_gate in batch.into_array() {
            self.0.next(encrypted_gate);
            if !self.0.wants_gates() {
                // Skipping any remaining gates which may have been used to pad the last batch.
                return;
            }
        }
    }

    /// Returns the encoded outputs of the circuit, and the hash of the
    /// encrypted gates if present.
    pub fn finish(self) -> Result<AuthEvalOutput, AuthEvaluatorError> {
        self.0.finish()
    }
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
                        gates[and_count], 
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
                hash ^= cipher.tccr(Block::new((and_count as u128).to_be_bytes()), share);
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