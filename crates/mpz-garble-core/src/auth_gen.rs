use core::fmt;

use crate::{
    circuit::{sigma, AuthHalfGate, AuthHalfGateBatch}, 
    fpre::{AuthBitShare, AuthTripleShare, FpreGen}, 
    DEFAULT_BATCH_SIZE,
    Party
};
use mpz_circuits::{
    types::{BinaryRepr, TypeError},
    Circuit, Gate, CircuitError
};
use mpz_core::{
    aes::{FixedKeyAes, FIXED_KEY_AES},
    Block,
};
use mpz_memory_core::correlated::{Key, Mac, Delta};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

const SELECT_MASK: [Block; 2] = [Block::ZERO, Block::ONE];
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

#[inline]
pub(crate) fn sigma_share(
    triple: &mut AuthTripleShare, 
    px: bool, 
    py: bool, 
    delta_a: &Block
) -> AuthBitShare {
    let mut sigma_share = triple.z.clone();

    if px {
        sigma_share = sigma_share + triple.y;
    }
    
    if py {
        sigma_share = sigma_share + triple.x;
    }

    if px && py {
        sigma_share.key = sigma_share.key + Key::from(*delta_a); 
    }

    sigma_share
}

#[inline]
pub(crate) fn and_gate(
    lx: &Block,
    ly: &Block,
    sx: &AuthBitShare,
    sy: &AuthBitShare,
    sz: &AuthBitShare,
    ss: &AuthBitShare,
    delta_a: &Block,
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

    let hx = sigma(j, *lx, cipher);
    let hy = sigma(k, *ly, cipher);
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

/// Output of the generator.
#[derive(Debug)]
pub struct AuthGenOutput {
    /// Output labels of the circuit.
    pub output_labels: Vec<Key>,
    /// Output auth bits of the circuit.
    pub output_auth_bits: Vec<AuthBitShare>,
    /// Authentication hash of the circuit.
    pub auth_hash: Block,
}

/// Garbled circuit generator.
#[derive(Debug, Default)]
pub struct AuthGen {
    labels: Vec<Block>, 
    auth_bits: Vec<AuthBitShare>,
    sigma_bits: Vec<AuthBitShare>,
    masked_values: Vec<bool>,
    // Preprocessed triples, consumed to generate sigma_bits
    triples: Vec<AuthTripleShare>,
    leaky_triples: Vec<AuthTripleShare>,
    permutation: Vec<usize>,
    seed: u64, // via secure coin toss
}

// TODO: separate the pre-processing from the generation into func ind, func dep

impl AuthGen {

    /// 1) Sets input auth bits and labels.
    /// 2) Uses auth bits from COT to set wire auth bits and output faulty triples.
    pub fn generate_pre_1<'a>(
        &'a mut self, 
        circ: &'a Circuit,
        delta: Delta,
        input_labels: Vec<Key>,
        input_auth_bits: Vec<AuthBitShare>,
        shares: Vec<AuthBitShare>,
    ) -> Result<(Vec<Block>, Vec<Block>), AuthGeneratorError> {

        if input_labels.len() != circ.input_len() || input_auth_bits.len() != circ.input_len() {
            return Err(CircuitError::InvalidInputCount(
                circ.input_len(),
                input_labels.len(),
            ))?;
        }

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.labels.len() {
            self.labels.resize(circ.feed_count(), Default::default());
            self.auth_bits.resize(circ.feed_count(), Default::default());
        }

        // Set input labels and auth bits
        let mut input_labels_iter = input_labels.into_iter();
        let mut input_auth_bits_iter = input_auth_bits.into_iter();
        for input in circ.inputs() {
            for (node, label) in input.iter().zip(input_labels_iter.by_ref()) {
                self.labels[node.id()] = label.into();
            }
            for (node, auth_bit) in input.iter().zip(input_auth_bits_iter.by_ref()) {
                self.auth_bits[node.id()] = auth_bit;
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
    pub fn generate_pre_2<'a>(
        &'a mut self, 
        delta: Delta,
        c: Vec<Block>, 
        g: &mut Vec<Block>, 
        gr: Vec<Block> // received
    ) -> Result<Vec<bool>, AuthGeneratorError> {
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
    pub fn generate_pre_3<'a>(
        &'a mut self, 
        delta: Delta,
        g: &mut Vec<Block>, 
        mut d: Vec<bool>, 
        dr: Vec<bool> // received
    ) -> Result<Vec<bool>, AuthGeneratorError> {
        let length = self.leaky_triples.len();
        for i in 0..length {
            d[i] = d[i] ^ dr[i];
            if d[i] {
                self.leaky_triples[i].z.value = !self.leaky_triples[i].z.value;
                g[i] = g[i] ^ delta.as_block();
            }
        }

        let total = self.leaky_triples.len();
        let bucket_size = total / self.triples.len();
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
    pub fn generate_pre_4<'a>(
        &'a mut self,
        data: Vec<bool>,
        data_recv: Vec<bool>, // received
    ) -> Result<(), AuthGeneratorError> {

        let total = self.leaky_triples.len();
        let bucket_size = total / self.triples.len();
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

    /// Generates the free gates for the circuit.
    pub fn generate_free<'a>(
        &'a mut self, 
        circ: &'a Circuit,
    ) -> Result<(), AuthGeneratorError> {
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
    pub fn generate_de<'a>(
        &'a mut self,
        circ: &'a Circuit,
    ) -> Result<(Vec<bool>, Vec<bool>), AuthGeneratorError> {
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
    pub fn generate<'a>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        px: Vec<bool>, // received
        py: Vec<bool>, // received
    ) -> Result<AuthEncryptedGateIter<'_, std::slice::Iter<'_, Gate>>, AuthGeneratorError> {
        // Validate inputs
        if px.len().min(py.len()) < circ.and_count() {
            return Err(AuthGeneratorError::InvalidPxPyCount {
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
                let ss = sigma_share(triple, px, py, delta.as_block());
                
                self.sigma_bits.push(ss);
                and_count += 1;
            }
        }
        Ok(AuthEncryptedGateIter::new(
            delta,
            circ.gates().iter(),
            circ.outputs(),
            &mut self.labels,
            &mut self.auth_bits,
            &mut self.sigma_bits,
            &mut self.masked_values,
            circ.and_count(),
        ))
    }
}

/// Iterator over the encrypted gates of a circuit.
pub struct AuthEncryptedGateIter<'a, I> {
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

impl<'a, I> fmt::Debug for AuthEncryptedGateIter<'a, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthEncryptedGateIter {{ .. }}")
    }
}

impl<'a, I> AuthEncryptedGateIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    fn new(
        delta: Delta,
        gates: I,
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

    /// Returns `true` if the generator has more encrypted gates to generate.
    #[inline]
    pub fn has_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Returns the encoded outputs of the circuit, and the hash of the
    /// encrypted gates if present.
    pub fn finish(
        mut self,
        masked_values: Vec<bool>
    ) -> Result<AuthGenOutput, AuthGeneratorError> {
        if self.has_gates() {
            return Err(AuthGeneratorError::NotFinished);
        }

        // Finish computing any "free" gates.
        if !self.complete {
            assert_eq!(self.next(), None);
        }

        let (output_labels, output_auth_bits): (Vec<_>, Vec<_>) = self
            .outputs
            .iter()
            .flat_map(|output| output.iter().map(|node| {
                let key = Key::from(self.labels[node.id()]);
                let auth_bit = self.auth_bits[node.id()];
                (key, auth_bit)
            }))
            .unzip();


        // TODO: Set intermediate masked values

        let mut auth_hash = Block::ZERO;
        let mut and_count = 0;
        let delta = self.delta.as_block();
        
        for gate in self.gates {
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
                auth_hash ^= sigma(Block::new((and_count as u128).to_be_bytes()), share, self.cipher);
                and_count += 1;
            }
        }
        
        Ok(AuthGenOutput { output_labels, output_auth_bits, auth_hash })
    }
}

impl<'a, I> Iterator for AuthEncryptedGateIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    type Item = AuthHalfGate;

    // Check this. It doesn't make sense that only AND gates are done here for half-gates...
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::And { x, y, z } => {
                    let lx = self.labels[x.id()];
                    let ly = self.labels[y.id()];
                    let sx = self.auth_bits[x.id()];
                    let sy = self.auth_bits[y.id()];

                    // Get sigma share for this gate
                    let ss = self.sigma_bits[self.counter];

                    // Get auth bit share for output wire
                    let sz = self.auth_bits[z.id()];

                    // Garble the gate and compute output label
                    let (half_gate, lz) = and_gate(&lx, &ly, &sx, &sy, &sz, &ss, self.delta.as_block(), self.cipher, self.gid);
                    self.labels[z.id()] = lz;
                    
                    self.gid += 2;
                    self.counter += 1;

                    return Some(half_gate);
                }
                Gate::Xor { x, y, z } => {
                    self.labels[z.id()] = self.labels[x.id()] ^ self.labels[y.id()];
                }
                Gate::Inv { x, z } => {
                    self.labels[z.id()] = self.labels[x.id()] ^ self.delta.as_block();
                }
            }
        }

        None
    }
}

/// Iterator returned by [`Generator::generate_batched`].
#[derive(Debug)]
pub struct AuthEncryptedGateBatchIter<'a, I: Iterator, const N: usize = DEFAULT_BATCH_SIZE>(
    AuthEncryptedGateIter<'a, I>,
);

impl<'a, I, const N: usize> AuthEncryptedGateBatchIter<'a, I, N>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if the generator has more encrypted gates to generate.
    pub fn has_gates(&self) -> bool {
        self.0.has_gates()
    }

    /// Returns the encoded outputs of the circuit, and the hash of the
    /// encrypted gates if present.
    pub fn finish(self, masked_values: Vec<bool>) -> Result<AuthGenOutput, AuthGeneratorError> {
        self.0.finish(masked_values)
    }
}

impl<'a, I, const N: usize> Iterator for AuthEncryptedGateBatchIter<'a, I, N>
where
    I: Iterator<Item = &'a Gate>,
{
    type Item = AuthHalfGateBatch<N>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if !self.has_gates() {
            return None;
        }

        let mut batch = [AuthHalfGate::default(); N];
        let mut i = 0;
        for gate in self.0.by_ref() {
            batch[i] = gate;
            i += 1;

            if i == N {
                break;
            }
        }

        Some(AuthHalfGateBatch::new(batch))
    }
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
        for gate in self.circ.gates() {
            match gate {
                Gate::Xor { x, y, z } => {
                    self.auth_bits[z.id()] = self.auth_bits[x.id()] + self.auth_bits[y.id()];
                }
                Gate::Inv { x, z } => {
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

        let delta = self.fpre.delta_a;
        
        let mut and_gates = Vec::with_capacity(self.circ.and_count());
        let mut and_count = 0;
        
        // Reserve space for sigma bits
        self.sigma_bits.clear();
        self.sigma_bits.reserve(self.circ.and_count());

        for gate in self.circ.gates() {
            match gate {
                Gate::And { x, y, z } => {
                    let lx = self.labels[x.id()];
                    let ly = self.labels[y.id()];
                    let sx = self.auth_bits[x.id()];
                    let sy = self.auth_bits[y.id()];
                    let triple = &mut self.fpre.triple_shares[and_count];

                    // Calculate adjusted px and py values
                    let px = sx.bit() ^ triple.x.bit() ^ px_vec[and_count];
                    let py = sy.bit() ^ triple.y.bit() ^ py_vec[and_count];

                    // Compute sigma share for this gate
                    let ss = sigma_share(triple, px, py, delta.as_block());

                    // Get preprocessed share for wire z
                    let sz = self.auth_bits[z.id()];

                    // Garble the gate and compute output label
                    let (half_gate, lz) = and_gate(&lx, &ly, &sx, &sy, &sz, &ss, delta.as_block(), cipher, self.gid);
                    self.labels[z.id()] = lz;
                    
                    self.sigma_bits.push(ss);
                    and_gates.push(half_gate);
                    and_count += 1;
                    self.gid += 2;
                }
                Gate::Xor { x, y, z } => {
                    self.labels[z.id()] = self.labels[x.id()] ^ self.labels[y.id()];
                }
                Gate::Inv { x, z } => {
                    self.labels[z.id()] = self.labels[x.id()] ^ delta.as_block();
                }
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