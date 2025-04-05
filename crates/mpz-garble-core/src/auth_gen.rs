use core::fmt;

use crate::{
    circuit::{AuthHalfGate, AuthHalfGateBatch}, 
    fpre::{AuthBitShare, AuthTripleShare}, 
    DEFAULT_BATCH_SIZE,
};
use mpz_circuits::{
    types::{BinaryRepr, TypeError},
    Circuit, Gate, CircuitError
};
use mpz_core::{
    aes::{FixedKeyAes, FIXED_KEY_AES},
    Block,
};
use mpz_memory_core::correlated::{Key, Delta};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

const SELECT_MASK: [Block; 2] = [Block::ZERO, Block::ONES];
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
pub(crate) fn sigma_share(
    triple: &mut AuthTripleShare, 
    px: bool, 
    py: bool, 
    delta: &Block
) -> AuthBitShare {
    let mut sigma_share = triple.z.clone();

    if px {
        sigma_share = sigma_share + triple.y;
    }
    
    if py {
        sigma_share = sigma_share + triple.x;
    }

    if px && py {
        sigma_share.key = sigma_share.key + Key::from(*delta); 
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
    delta: &Block,
    cipher: &FixedKeyAes,  
    gid: usize,
) -> (AuthHalfGate, Block) {
    // Compute 1-bit labels
    let lx1 = lx ^ delta;
    let ly1 = ly ^ delta;
    
    // Pre-compute all hashes
    let j = Block::new((gid as u128).to_be_bytes());
    let k = Block::new(((gid + 1) as u128).to_be_bytes());
    
    let mut h = [*lx, *ly, lx1, ly1];
    cipher.tccr_many(&[j, k, j, k], &mut h);
    let [hx, hy, hx1, hy1] = h;

    // let hx = sigma(j, *lx, cipher);
    // let hy = sigma(k, *ly, cipher);
    // let hx1 = sigma(j, lx1, cipher);
    // let hy1 = sigma(k, ly1, cipher);
    
    let g_0 = hx ^ hx1 ^ sy.key.as_block() ^ delta.mul_bool(sy.bit());
              
    let g_1 = hy ^ hy1 ^ sx.key.as_block() ^ delta.mul_bool(sx.bit()) ^ lx;
    
    // Compute output label
    let lz = hx ^ hy ^ sz.key.as_block() ^ delta.mul_bool(sz.bit()) ^ 
            ss.key.as_block() ^ delta.mul_bool(ss.bit());
    
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
pub struct AuthGen {
    cipher: &'static FixedKeyAes,
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

// TODO: separate the pre-processing from the generation into func ind, func dep
// TODO: set input labels at the end

impl AuthGen {

    /// Create a new AuthGen with seed from coin-tossing
    pub fn new(seed: u64, bucket_size: usize) -> Self {
        Self {
            cipher: &(*FIXED_KEY_AES),
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
    pub fn generate_pre_1<'a>(
        &'a mut self, 
        circ: &'a Circuit,
        delta: Delta,
        input_auth_bits: Vec<AuthBitShare>,
        shares: Vec<AuthBitShare>,
    ) -> Result<(Vec<Block>, Vec<Block>), AuthGeneratorError> {

        if input_auth_bits.len() != circ.input_len() {
            return Err(CircuitError::InvalidInputCount(
                circ.input_len(),
                input_auth_bits.len(),
            ))?;
        }

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.labels.len() {
            self.auth_bits.resize(circ.feed_count(), Default::default());
        }

        // Set input labels and auth bits
        let mut input_auth_bits_iter = input_auth_bits.into_iter();
        for input in circ.inputs() {
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
                ^ (SELECT_MASK[self.leaky_triples[i].y.bit() as usize] & delta.as_block());

            g[i] = c[i] ^ h2d(self.leaky_triples[i].x.key.into(), delta.into_inner(), self.cipher);
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
            let mut s = h2(self.leaky_triples[i].x.mac.as_block().clone(), self.leaky_triples[i].x.key.as_block().clone(), self.cipher);
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
    pub fn generate_pre_4<'a>(
        &'a mut self,
        data: Vec<bool>,
        data_recv: Vec<bool>, // received
    ) -> Result<(), AuthGeneratorError> {

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
        input_labels: Vec<Key>,
        px: Vec<bool>, // received
        py: Vec<bool>, // received
    ) -> Result<AuthEncryptedGateIter<'_, std::slice::Iter<'_, Gate>>, AuthGeneratorError> {
        
        if input_labels.len() != circ.input_len() {
            return Err(CircuitError::InvalidInputCount(
                circ.input_len(),
                input_labels.len(),
            ))?;
        }

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.labels.len() {
            self.labels.resize(circ.feed_count(), Default::default());
        }

        // Set input labels
        let mut input_labels_iter = input_labels.into_iter();
        for input in circ.inputs() {
            for (node, label) in input.iter().zip(input_labels_iter.by_ref()) {
                self.labels[node.id()] = label.into();
            }
        }
        
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

        self.masked_values.resize(circ.feed_count(), false);
        Ok(AuthEncryptedGateIter::new(
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

    /// Returns an iterator over the batched encrypted gates of a circuit.
    pub fn generate_batched<'a>(
        &'a mut self,
        circ: &'a Circuit,
        delta: Delta,
        input_labels: Vec<Key>,
        px: Vec<bool>,
        py: Vec<bool>,
    ) -> Result<AuthEncryptedGateBatchIter<'_, std::slice::Iter<'_, Gate>>, AuthGeneratorError> {
        self.generate(circ, delta, input_labels, px, py)
            .map(AuthEncryptedGateBatchIter)
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

        // let (output_labels, output_auth_bits): (Vec<_>, Vec<_>) = self
        //     .outputs
        //     .iter()
        //     .flat_map(|output| output.iter().map(|node| {
        //         let key = Key::from(self.labels[node.id()]);
        //         let auth_bit = self.auth_bits[node.id()];
        //         (key, auth_bit)
        //     }))
        //     .unzip();

        let mut output_labels = Vec::new();
        let mut output_auth_bits = Vec::new();

        for output in self.outputs.iter() {
            for node in output.iter() {
                output_labels.push(Key::from(self.labels[node.id()]));
                output_auth_bits.push(self.auth_bits[node.id()]);
            }
        }

        self.masked_values.copy_from_slice(&masked_values);

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
        
        Ok(AuthGenOutput { output_labels, output_auth_bits, auth_hash })
    }
}

impl<'a, I> Iterator for AuthEncryptedGateIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    type Item = AuthHalfGate;

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

                    // If we have generated all AND gates, we can compute
                    // the rest of the "free" gates.
                    if !self.has_gates() {
                        assert!(self.next().is_none());

                        self.complete = true;
                    }

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