use std::{fmt, ops::Range};
use mpz_memory_core::correlated::{Mac, Delta, Key};

use mpz_circuits::{
    Circuit, CircuitError, Gate,
};
use mpz_core::{
    aes::{FixedKeyAes, FIXED_KEY_AES},
    Block,
};

use crate::{fpre::{AuthBitShare, AuthTripleShare}, circuit::{AuthHalfGate, AuthHalfGateBatch}, DEFAULT_BATCH_SIZE};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// Errors that can occur during garbled circuit evaluation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum AuthEvaluatorError {
    #[error(transparent)]
    CircuitError(#[from] CircuitError),
    #[error("evaluator not finished")]
    NotFinished,
    #[error("MAC verification failed at gate {0}")]
    MacCheckFailed(usize), 
    #[error("expected {expected} auth bits, got {actual}")]
    InvalidAuthBitCount { expected: usize, actual: usize },
    #[error("expected {expected} derandomization bits, got {actual}")]
    InvalidDerandCount { expected: usize, actual: usize },
    #[error("expected {expected} input MACs, got {actual}")]
    InvalidInputMacCount { expected: usize, actual: usize },
    #[error("expected {expected} masked inputs, got {actual}")]
    InvalidMaskedInputCount { expected: usize, actual: usize },
    #[error("expected {expected} output MACs, got {actual}")]
    InvalidOutputMacCount { expected: usize, actual: usize },
}

// hash helper
fn h2d(a: Block, b: Block, cipher: &FixedKeyAes) -> Block {
    let mut d = [a, a ^ b];
    cipher.cr_many( &mut d);
    d[0] = d[0] ^ d[1]; 
    return d[0] ^ b;
}

// hash helper
fn h2(a: Block, b: Block, cipher: &FixedKeyAes) -> Block {
    let mut d = [a, b];
    cipher.cr_many(&mut d);
    d[0] = d[0] ^ d[1];
    d[0] = d[0] ^ a;
    return d[0] ^ b;
}

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
    let g_0 = encrypted_gate.gates[0] ^ sy.mac.as_block();
    let g_1 = encrypted_gate.gates[1] ^ sx.mac.as_block();

    let j = Block::new((gid as u128).to_be_bytes());
    let k = Block::new(((gid + 1) as u128).to_be_bytes());

    let mut h = [lx, ly];
    cipher.tccr_many(&[j, k], &mut h);
    let [hx, hy] = h;

    let sz_mac = sz.mac.as_block();
    let ss_mac = ss.mac.as_block();

    let lz = hx ^ hy ^ sz_mac ^ ss_mac ^ (g_0.mul_bool(za)) ^ ((g_1^lx).mul_bool(zb));
    let zc = lz.lsb() ^ encrypted_gate.mask;
    
    (lz, zc)
}


#[inline]
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

#[inline]
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

/// Output of the authenticated evaluator.
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

/// Authenticated garbled circuit evaluator.
pub struct AuthEval {
    cipher: &'static FixedKeyAes,
    labels: Vec<Block>, 
    auth_bits: Vec<AuthBitShare>,
    sigma_bits: Vec<AuthBitShare>,
    masked_values: Vec<bool>,
    triples: Vec<AuthTripleShare>,
    leaky_triples: Vec<AuthTripleShare>,
    permutation: Vec<usize>,
    seed: u64, // via secure coin toss
    bucket_size: usize,
}

impl AuthEval {

    /// Create a new AuthEval with seed from coin-tossing
    pub fn new(seed: u64, bucket_size: usize) -> Self {
        Self {
            cipher: &(*FIXED_KEY_AES),
            labels: Vec::new(),
            auth_bits: Vec::new(),
            sigma_bits: Vec::new(),
            masked_values: Vec::new(),
            triples: Vec::new(),
            leaky_triples: Vec::new(),
            permutation: Vec::new(),
            seed,
            bucket_size,
        }
    }

    /// Set input auth bits, begin generation of triples
    pub fn evaluate_pre_1<'a>(
        &'a mut self, 
        circ: &'a Circuit,
        delta: Delta,
        input_auth_bits: &[AuthBitShare],
        shares: &[AuthBitShare],
    ) -> Result<(Vec<Block>, Vec<Block>), AuthEvaluatorError> {

        if input_auth_bits.len() != circ.inputs().len() {
            return Err(AuthEvaluatorError::InvalidAuthBitCount {
                expected: circ.inputs().len(),
                actual: input_auth_bits.len(),
            });
        }

        if circ.feed_count() > self.auth_bits.len() {
            self.auth_bits.resize(circ.feed_count(), Default::default());
        }

        self.auth_bits[..input_auth_bits.len()].copy_from_slice(input_auth_bits);

        let mut count = 0;
        for gate in circ.gates() {
            if let Gate::And { x: _, y: _, z } = gate {
                self.auth_bits[z.id()] = shares[count];
                count += 1;
            }
        }

        let remaining_shares = shares.len() - count;
        let length = remaining_shares / 3;
        for i in 0..length {
            let base_idx = count + (3 * i);
            self.leaky_triples.push(AuthTripleShare {
                x: shares[base_idx],
                y: shares[base_idx + 1],
                z: shares[base_idx + 2]
            });
        }

        let length = self.leaky_triples.len();
        let mut c = vec![Block::ZERO; length];
        let mut g = vec![Block::ZERO; length];

        for i in 0..length {
            c[i] = self.leaky_triples[i].y.mac.as_block().clone()
                ^ self.leaky_triples[i].y.key.as_block().clone()
                ^ (delta.mul_bool(self.leaky_triples[i].y.bit()));

            g[i] = c[i] ^ h2d(self.leaky_triples[i].x.key.into(), delta.into_inner(), self.cipher);
        }
        Ok((c, g))
    }

    /// Triple generation, Round 2
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
            let mut s = h2(self.leaky_triples[i].x.mac.as_block().clone(), self.leaky_triples[i].x.key.as_block().clone(), self.cipher);
            s = s ^ self.leaky_triples[i].z.mac.as_block().clone() ^ self.leaky_triples[i].z.key.as_block().clone();
            s = s ^ (gr[i] ^ c[i]).mul_bool(self.leaky_triples[i].x.bit());
            g[i] = s ^ delta.mul_bool(self.leaky_triples[i].z.bit());
            d[i] = g[i].lsb();
        }

        Ok(d)
    }

    /// Triple generation, Round 3
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
            let idx = rng.random_range(0..=i);
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

    /// Triple generation, Round 4
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
    
            let mut combined_share = self.leaky_triples[base_idx].clone();
    
            for j in 1..bucket_size {
                let idx_j = self.permutation[i*bucket_size + j];
    
                combined_share.x = combined_share.x + self.leaky_triples[idx_j].x;
                combined_share.z = combined_share.z + self.leaky_triples[idx_j].z;
    
                if final_data[i*bucket_size + j] {
                    combined_share.z = combined_share.z + self.leaky_triples[idx_j].x;
                }
            }
            self.triples.push(combined_share);
        }
        Ok(())
    }

    /// Circuit dependent local preprocessing.
    pub fn evaluate_free<'a>(
        &'a mut self, 
        circ: &'a Circuit,
    ) -> Result<(), AuthEvaluatorError> {
        for gate in circ.gates() {
            match gate {
                Gate::Xor { x, y, z } => {
                    self.auth_bits[z.id()] = self.auth_bits[x.id()] + self.auth_bits[y.id()];
                }
                Gate::Inv { x, z } => {
                    self.auth_bits[z.id()] = self.auth_bits[x.id()];
                }
                Gate::Id { x, z } => {
                    self.auth_bits[z.id()] = self.auth_bits[x.id()];
                }
                Gate::And { .. } => {
                    // AND gates are handled separately
                }
            }
        }
        Ok(())
    }

    /// Generates the derandomized bits for circuit-dependent AND gate preprocessing.
    pub fn evaluate_de<'a>(
        &'a mut self,
        circ: &'a Circuit,
    ) -> Result<(Vec<bool>, Vec<bool>), AuthEvaluatorError> {
        let mut px = Vec::new();
        let mut py = Vec::new();
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

    /// Generates a consumer over the encrypted gates of a circuit, finish circuit dependent preprocessing
    pub fn evaluate<'a>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        input_labels: &[Mac],
        masked_inputs: Vec<bool>,
        px: Vec<bool>, // received
        py: Vec<bool>, // received
    ) -> Result<AuthEncryptedGateConsumer<'a, std::slice::Iter<'a, Gate>>, AuthEvaluatorError> {

        if input_labels.len() != circ.inputs().len() {
            return Err(AuthEvaluatorError::InvalidInputMacCount {
                expected: circ.inputs().len(),
                actual: input_labels.len(),
            });
        }

        if masked_inputs.len() != circ.inputs().len() {
            return Err(AuthEvaluatorError::InvalidMaskedInputCount {
                expected: circ.inputs().len(),
                actual: masked_inputs.len(),
            });
        }

        if circ.feed_count() > self.labels.len() || circ.feed_count() > self.masked_values.len() {
            self.labels.resize(circ.feed_count(), Default::default());
            self.masked_values.resize(circ.feed_count(), false);
        }
        
        self.labels[..input_labels.len()].copy_from_slice(Mac::as_blocks(input_labels));
        self.masked_values[..masked_inputs.len()].copy_from_slice(&masked_inputs);

        if px.len().min(py.len()) < circ.and_count() {
            return Err(AuthEvaluatorError::InvalidDerandCount {
                expected: circ.and_count(),
                actual: px.len().min(py.len()),
            });
        }

        let mut and_count = 0;
        
        self.sigma_bits.reserve(circ.and_count());

        for gate in circ.gates() {
            if let Gate::And { x, y, z: _ } = gate {
                let sx = self.auth_bits[x.id()];
                let sy = self.auth_bits[y.id()];
                let triple = &mut self.triples[and_count];

                let px = sx.bit() ^ triple.x.bit() ^ px[and_count];
                let py = sy.bit() ^ triple.y.bit() ^ py[and_count];

                // Compute auth_bit for output wire of this AND gate
                let ss = sigma_share(triple, px, py);
                
                self.sigma_bits.push(ss);
                and_count += 1;
            }
        }

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

    /// Generates a consumer over the batched encrypted gates of a circuit, finish circuit dependent preprocessing
    pub fn evaluate_batched<'a>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        input_labels: &[Mac], 
        masked_inputs: Vec<bool>,
        px: Vec<bool>,
        py: Vec<bool>,
    ) -> Result<AuthEncryptedGateBatchConsumer<'a, std::slice::Iter<'a, Gate>>, AuthEvaluatorError> {
        self.evaluate(circ, delta, input_labels, masked_inputs, px, py).map(AuthEncryptedGateBatchConsumer)
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
   /// Iterator over the gates to check authenticity.
   gates_check: I,
   /// Circuit outputs.
   outputs: Range<usize>,
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
        gates_check: I,
        outputs: Range<usize>,
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
            gates_check,
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
                Gate::Id { x, z } => {
                    self.labels[z.id()] = self.labels[x.id()];
                    self.masked_values[z.id()] = self.masked_values[x.id()];
                }
                Gate::And { x, y, z } => {
                    // Get labels for input wires
                    let lx = self.labels[x.id()];
                    let ly = self.labels[y.id()];
                    
                    // Get input auth_bits
                    let sx = self.auth_bits[x.id()];
                    let sy = self.auth_bits[y.id()];

                    // Get AND of input auth_bits
                    let ss = self.sigma_bits[self.counter];

                    // Get output auth_bit for wire
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

                    // If we have more AND gates to evaluate, return.
                    if self.wants_gates() {
                        return;
                    }
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

        let output_labels = Mac::from_blocks(self.labels[self.outputs.clone()].to_vec());
        let output_auth_bits = self.auth_bits[self.outputs.clone()].to_vec();
        let masked_output_values = self.masked_values[self.outputs.clone()].to_vec();

        let mut auth_hash = Block::ZERO;
        let mut and_count = 0;
        let delta = self.delta.as_block();
        
        for gate in self.gates_check {
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